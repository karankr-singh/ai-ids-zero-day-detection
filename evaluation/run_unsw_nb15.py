"""Reproducible UNSW-NB15 evaluation for the AI-IDS Isolation Forest.

The official test split is used only for final evaluation. A calibration subset
of normal training records determines the anomaly-score threshold.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
import sklearn
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler


LABEL_COLUMN = "label"
CATEGORY_COLUMN = "attack_cat"
DROP_COLUMNS = {"id", "attack_cat", "label"}

# Official 45-column UNSW-NB15 schema, used by headerless tab-separated exports.
UNSW_NB15_COLUMNS = [
    "id", "dur", "proto", "service", "state", "spkts", "dpkts", "sbytes", "dbytes",
    "rate", "sttl", "dttl", "sload", "dload", "sloss", "dloss", "sinpkt", "dinpkt",
    "sjit", "djit", "swin", "stcpb", "dtcpb", "dwin", "tcprtt", "synack", "ackdat",
    "smean", "dmean", "trans_depth", "response_body_len", "ct_srv_src", "ct_state_ttl",
    "ct_dst_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm",
    "is_ftp_login", "ct_ftp_cmd", "ct_flw_http_mthd", "ct_src_ltm", "ct_srv_dst",
    "is_sm_ips_ports", "attack_cat", "label",
]
DEFAULT_SEED = 42

ZENODO_FILES = {
    "UNSW_NB15_training-set.csv": "b5a3168217dee84d94574e697130c8aa",
    "UNSW_NB15_testing-set.csv": "07a1566e74e89f4c970fd1dc3b5d554b",
}

def _md5(path: Path) -> str:
    digest = hashlib.md5()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def download_dataset(data_dir: Path, force: bool = False) -> tuple[Path, Path]:
    """Download the pinned UNSW-NB15 CSV split files and verify their checksums."""
    data_dir.mkdir(parents=True, exist_ok=True)
    paths = {}
    for filename, expected in ZENODO_FILES.items():
        target = data_dir / filename
        if target.exists() and not force and _md5(target) == expected:
            print(f"Using verified cached file: {target}")
            paths[filename] = target
            continue
        url = f"https://zenodo.org/records/3768048/files/{filename}?download=1"
        temp = target.with_suffix(target.suffix + ".part")
        request = urllib.request.Request(url, headers={"User-Agent": "AI-IDS-benchmark/1.0"})
        print(f"Downloading {filename} from Zenodo...")
        try:
            with urllib.request.urlopen(request, timeout=90) as response, temp.open("wb") as output:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    output.write(chunk)
            actual = _md5(temp)
            if actual != expected:
                raise ValueError(f"Checksum mismatch for {filename}: expected {expected}, got {actual}")
            temp.replace(target)
        except Exception:
            temp.unlink(missing_ok=True)
            raise
        print(f"Downloaded and verified: {target}")
        paths[filename] = target
    return paths["UNSW_NB15_training-set.csv"], paths["UNSW_NB15_testing-set.csv"]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_dataset(path: Path) -> pd.DataFrame:
    """Load headered CSV or headerless tab-separated official UNSW-NB15 data."""
    if not path.is_file():
        raise FileNotFoundError(f"Dataset file not found: {path}")

    # The Zenodo files currently used by this benchmark are tab-separated and
    # headerless. Other common UNSW-NB15 mirrors are comma-separated with headers.
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        first_line = stream.readline()
    delimiter = chr(9) if chr(9) in first_line else ","

    frame = pd.read_csv(path, sep=delimiter, low_memory=False)
    frame.columns = [str(column).strip().lower() for column in frame.columns]

    if LABEL_COLUMN not in frame.columns:
        # Re-read without a header and apply the published 45-column schema.
        frame = pd.read_csv(path, sep=delimiter, header=None, low_memory=False)
        if frame.shape[1] != len(UNSW_NB15_COLUMNS):
            raise ValueError(
                f"{path} has no 'label' header and contains {frame.shape[1]} columns; "
                f"expected {len(UNSW_NB15_COLUMNS)} for the headerless UNSW-NB15 format. "
                "Check the downloaded file and its delimiter."
            )
        frame.columns = UNSW_NB15_COLUMNS

    if frame.empty:
        raise ValueError(f"Dataset file is empty: {path}")
    if LABEL_COLUMN not in frame.columns:
        raise ValueError(f"{path} could not be parsed into the expected UNSW-NB15 schema.")
    return frame


def binary_labels(frame: pd.DataFrame, source: str) -> np.ndarray:
    values = pd.to_numeric(frame[LABEL_COLUMN], errors="coerce")
    if values.isna().any() or not set(values.unique()).issubset({0, 1}):
        raise ValueError(f"{source}: 'label' must contain only numeric 0/1 values.")
    return values.astype(int).to_numpy()


def feature_frame(frame: pd.DataFrame) -> pd.DataFrame:
    """Remove labels/identifiers and normalize mixed CSV column types."""
    X = frame.drop(columns=[c for c in DROP_COLUMNS if c in frame.columns]).copy()
    if X.empty:
        raise ValueError("No feature columns remain after removing labels/IDs.")
    for column in X.columns:
        if X[column].dtype == object:
            # Keep genuine categorical values categorical; normalize whitespace.
            X[column] = X[column].astype("string").str.strip()
            X[column] = X[column].replace({"": pd.NA, "nan": pd.NA, "None": pd.NA})
    return X


def make_pipeline(X: pd.DataFrame, estimators: int, seed: int) -> Pipeline:
    numeric = X.select_dtypes(include=["number"]).columns.tolist()
    categorical = [column for column in X.columns if column not in numeric]
    transformers = []
    if numeric:
        numeric_pipe = Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
        ])
        transformers.append(("numeric", numeric_pipe, numeric))
    if categorical:
        categorical_pipe = Pipeline([
            ("imputer", SimpleImputer(strategy="most_frequent")),
            ("onehot", OneHotEncoder(handle_unknown="ignore")),
        ])
        transformers.append(("categorical", categorical_pipe, categorical))
    preprocessing = ColumnTransformer(transformers, remainder="drop")
    return Pipeline([
        ("preprocess", preprocessing),
        ("model", IsolationForest(
            n_estimators=estimators,
            contamination="auto",
            random_state=seed,
            n_jobs=-1,
        )),
    ])


def precision_at_k(y_true: np.ndarray, anomaly_scores: np.ndarray, k: int) -> dict:
    count = min(max(int(k), 1), len(y_true))
    selected = np.argsort(anomaly_scores)[-count:]
    return {
        "requested_k": int(k),
        "evaluated_k": int(count),
        "precision_at_k": float(np.mean(y_true[selected] == 1)),
        "attacks_in_top_k": int(np.sum(y_true[selected] == 1)),
    }


def evaluate(
    train_path: Path,
    test_path: Path,
    output_dir: Path,
    *,
    seed: int = DEFAULT_SEED,
    validation_fraction: float = 0.20,
    target_fpr: float = 0.05,
    estimators: int = 200,
    top_k: int = 100,
) -> dict:
    if not 0 < validation_fraction < 1:
        raise ValueError("validation_fraction must be between 0 and 1.")
    if not 0 < target_fpr < 1:
        raise ValueError("target_fpr must be between 0 and 1.")
    if estimators < 1 or top_k < 1:
        raise ValueError("estimators and top_k must be positive.")

    train = load_dataset(train_path)
    test = load_dataset(test_path)
    y_train_all = binary_labels(train, "training data")
    y_test = binary_labels(test, "test data")

    # Only labeled-normal rows from the official training file are eligible.
    normal_train = feature_frame(train.loc[y_train_all == 0].reset_index(drop=True))
    if len(normal_train) < 10:
        raise ValueError("At least 10 normal training rows are required.")
    X_fit, X_cal = train_test_split(
        normal_train,
        test_size=validation_fraction,
        random_state=seed,
        shuffle=True,
    )

    X_test = feature_frame(test)
    # Align test schema to training schema; extra test columns are ignored.
    X_test = X_test.reindex(columns=normal_train.columns)

    pipeline = make_pipeline(X_fit, estimators, seed)
    pipeline.fit(X_fit)  # No attack rows are passed to fit.

    calibration_scores = pipeline.score_samples(X_cal)
    # Isolation Forest: lower score means more anomalous. Calibrate using
    # normal-only validation records, independently of the official test set.
    threshold = float(np.quantile(calibration_scores, target_fpr))
    test_scores = pipeline.score_samples(X_test)
    y_pred = (test_scores < threshold).astype(int)
    anomaly_rank_scores = -test_scores

    tn, fp, fn, tp = confusion_matrix(y_test, y_pred, labels=[0, 1]).ravel()
    metrics = {
        "roc_auc": float(roc_auc_score(y_test, anomaly_rank_scores))
        if len(np.unique(y_test)) == 2 else None,
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "f1": float(f1_score(y_test, y_pred, zero_division=0)),
        "precision_at_k": precision_at_k(y_test, anomaly_rank_scores, top_k),
        "confusion_matrix": {
            "labels": ["normal", "attack"],
            "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        },
        "false_positive_rate": float(fp / (fp + tn)) if fp + tn else None,
        "false_negative_rate": float(fn / (fn + tp)) if fn + tp else None,
    }

    per_category = {}
    if CATEGORY_COLUMN in test.columns:
        categories = test[CATEGORY_COLUMN].fillna("Unknown").astype(str)
        for category in sorted(categories.unique()):
            mask = categories.to_numpy() == category
            positives = y_test[mask] == 1
            if positives.any():
                per_category[category] = {
                    "attack_records": int(positives.sum()),
                    "detected": int(np.sum(y_pred[mask][positives] == 1)),
                    "recall": float(np.mean(y_pred[mask][positives] == 1)),
                }

    report = {
        "benchmark": "UNSW-NB15",
        "evaluation_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "model": "sklearn.ensemble.IsolationForest",
        "metrics": metrics,
        "threshold_calibration": {
            "method": "lower quantile of normal-only calibration anomaly scores",
            "target_false_positive_rate": target_fpr,
            "score_threshold": threshold,
            "calibration_normal_records": int(len(X_cal)),
            "calibration_observed_fraction_below_threshold": float(
                np.mean(calibration_scores < threshold)
            ),
        },
        "data": {
            "training_file": str(train_path),
            "training_sha256": sha256_file(train_path),
            "official_training_rows": int(len(train)),
            "official_training_normal_rows": int(np.sum(y_train_all == 0)),
            "official_training_attack_rows_excluded": int(np.sum(y_train_all == 1)),
            "fit_normal_rows": int(len(X_fit)),
            "calibration_normal_rows": int(len(X_cal)),
            "test_file": str(test_path),
            "test_sha256": sha256_file(test_path),
            "official_test_rows": int(len(test)),
            "test_normal_rows": int(np.sum(y_test == 0)),
            "test_attack_rows": int(np.sum(y_test == 1)),
            "feature_count_before_encoding": int(normal_train.shape[1]),
            "feature_columns": list(normal_train.columns),
            "test_columns_aligned_to_training": True,
        },
        "configuration": {
            "random_seed": seed,
            "validation_fraction_of_normal_training_rows": validation_fraction,
            "n_estimators": estimators,
            "target_fpr": target_fpr,
            "precision_at_k": top_k,
        },
        "per_attack_category": per_category,
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "scikit_learn": sklearn.__version__,
        },
        "integrity_notes": [
            "Only normal-labeled records from the official training CSV were used for fitting.",
            "The calibration subset contains only normal-labeled training records.",
            "The official test CSV was not used for fitting or threshold selection.",
            "The official test CSV was evaluated once after model and threshold selection.",
            "Anomaly scores are ranking scores, not probabilities or confidence values.",
        ],
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "unsw_nb15_metrics.json"
    output_file.write_text(json.dumps(report, indent=2, allow_nan=False), encoding="utf-8")
    print(json.dumps({
        "output": str(output_file),
        "metrics": metrics,
        "threshold": threshold,
        "fit_normal_rows": len(X_fit),
        "calibration_normal_rows": len(X_cal),
        "test_rows": len(test),
    }, indent=2))
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train-csv", type=Path)
    parser.add_argument("--test-csv", type=Path)
    parser.add_argument("--download-data", action="store_true", help="Download and verify UNSW-NB15 CSV files")
    parser.add_argument("--data-dir", type=Path, default=Path("datasets/unsw_nb15"))
    parser.add_argument("--force-download", action="store_true", help="Redownload even if cached files verify")
    parser.add_argument("--output-dir", type=Path, default=Path("results/unsw_nb15"))
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--validation-fraction", type=float, default=0.20)
    parser.add_argument("--target-fpr", type=float, default=0.05)
    parser.add_argument("--estimators", type=int, default=200)
    parser.add_argument("--top-k", type=int, default=100)
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.download_data:
        if args.train_csv or args.test_csv:
            raise SystemExit("Use --download-data or explicit CSV paths, not both.")
        train_csv, test_csv = download_dataset(args.data_dir, force=args.force_download)
    else:
        if not args.train_csv or not args.test_csv:
            raise SystemExit("Provide --train-csv and --test-csv, or use --download-data.")
        train_csv, test_csv = args.train_csv, args.test_csv
    evaluate(
        train_csv, test_csv, args.output_dir,
        seed=args.seed,
        validation_fraction=args.validation_fraction,
        target_fpr=args.target_fpr,
        estimators=args.estimators,
        top_k=args.top_k,
    )
