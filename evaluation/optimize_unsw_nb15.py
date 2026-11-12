"""Train-partition-only model and threshold optimization for UNSW-NB15.

No official test rows are loaded by this experiment. Model selection uses a
normal-only fit set, a separate normal-only threshold-calibration set, and
held-out labeled rows from the official training partition for validation.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score, confusion_matrix, f1_score, precision_score,
    recall_score, roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.neighbors import LocalOutlierFactor
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.svm import OneClassSVM

from evaluation.run_unsw_nb15 import (
    CATEGORY_COLUMN, DEFAULT_SEED, binary_labels, feature_frame,
    load_dataset, sha256_file,
)

DEFAULT_FPRS = (0.01, 0.025, 0.05, 0.075, 0.10, 0.15)


def _preprocessor(X: pd.DataFrame) -> ColumnTransformer:
    numeric = X.select_dtypes(include=["number"]).columns.tolist()
    categorical = [c for c in X.columns if c not in numeric]
    transformers = []
    if numeric:
        transformers.append(("numeric", Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scale", StandardScaler()),
        ]), numeric))
    if categorical:
        transformers.append(("categorical", Pipeline([
            ("imputer", SimpleImputer(strategy="most_frequent")),
            ("onehot", OneHotEncoder(handle_unknown="ignore")),
        ]), categorical))
    return ColumnTransformer(transformers, remainder="drop")


def _models(seed: int, max_samples: int) -> dict:
    return {
        "isolation_forest": IsolationForest(
            n_estimators=200, contamination="auto",
            max_samples=min(max_samples, 8192), random_state=seed, n_jobs=-1,
        ),
        "local_outlier_factor": LocalOutlierFactor(
            n_neighbors=35, novelty=True, contamination="auto", n_jobs=-1,
        ),
        "one_class_svm": OneClassSVM(kernel="rbf", gamma="scale", nu=0.05),
    }


def _metric_row(y: np.ndarray, pred: np.ndarray, threshold_fpr: float,
                threshold: float, model_name: str) -> dict:
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {
        "model": model_name,
        "target_calibration_fpr": float(threshold_fpr),
        "score_threshold": float(threshold),
        "validation_accuracy": float(accuracy_score(y, pred)),
        "validation_precision": float(precision_score(y, pred, zero_division=0)),
        "validation_recall": float(recall_score(y, pred, zero_division=0)),
        "validation_f1": float(f1_score(y, pred, zero_division=0)),
        "validation_fpr": float(fp / (fp + tn)) if fp + tn else None,
        "validation_fnr": float(fn / (fn + tp)) if fn + tp else None,
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def run_optimization(
    train_path: Path,
    output_dir: Path,
    *,
    seed: int = DEFAULT_SEED,
    validation_fraction: float = 0.20,
    max_fit_samples: int = 15000,
    max_validation_samples: int = 12000,
    permutation_repeats: int = 2,
    max_validation_fpr: float = 0.10,
) -> dict:
    if not 0 < validation_fraction < 0.5:
        raise ValueError("validation_fraction must be between 0 and 0.5.")
    if max_fit_samples < 100 or max_validation_samples < 100:
        raise ValueError("Sample limits must be at least 100.")
    if permutation_repeats < 1:
        raise ValueError("permutation_repeats must be positive.")
    if not 0 < max_validation_fpr <= 1:
        raise ValueError("max_validation_fpr must be in (0, 1].")

    frame = load_dataset(train_path)
    labels = binary_labels(frame, "official training partition")
    X_all = feature_frame(frame)
    normal_idx = np.flatnonzero(labels == 0)
    attack_idx = np.flatnonzero(labels == 1)
    if len(normal_idx) < 100 or len(attack_idx) < 10:
        raise ValueError("Training partition needs at least 100 normal and 10 attack rows.")

    # Three disjoint normal-only subsets: fitting, threshold calibration,
    # and validation. Attack rows from the training partition are validation
    # examples only; none enter preprocessing/model fitting or calibration.
    fit_idx, remaining_idx = train_test_split(
        normal_idx, test_size=2 * validation_fraction,
        random_state=seed, shuffle=True,
    )
    cal_idx, normal_val_idx = train_test_split(
        remaining_idx, test_size=0.5, random_state=seed + 1, shuffle=True,
    )
    rng = np.random.default_rng(seed)
    if len(fit_idx) > max_fit_samples:
        fit_idx = np.sort(rng.choice(fit_idx, max_fit_samples, replace=False))
    val_idx = np.concatenate([normal_val_idx, attack_idx])
    if len(val_idx) > max_validation_samples:
        # Keep both classes represented; cap each class independently.
        val_parts = []
        for cls in (0, 1):
            candidates = val_idx[labels[val_idx] == cls]
            cap = max(1, int(max_validation_samples * len(candidates) / len(val_idx)))
            val_parts.append(rng.choice(candidates, min(len(candidates), cap), replace=False))
        val_idx = np.sort(np.concatenate(val_parts))

    X_fit = X_all.iloc[fit_idx].reset_index(drop=True)
    X_cal = X_all.iloc[cal_idx].reset_index(drop=True)
    X_val = X_all.iloc[val_idx].reset_index(drop=True)
    y_val = labels[val_idx]
    preprocessor = _preprocessor(X_fit)
    Z_fit = preprocessor.fit_transform(X_fit)
    Z_cal = preprocessor.transform(X_cal)
    Z_val = preprocessor.transform(X_val)

    model_results = []
    fitted = {}
    # LOF and RBF One-Class SVM have substantially higher memory/time costs
    # than Isolation Forest. Cap their fit subsets independently.
    per_model_fit_caps = {
        "isolation_forest": max_fit_samples,
        "local_outlier_factor": min(max_fit_samples, 5000),
        "one_class_svm": min(max_fit_samples, 5000),
    }
    for name, estimator in _models(seed, max_fit_samples).items():
        fit_limit = per_model_fit_caps[name]
        if Z_fit.shape[0] > fit_limit:
            model_rows = np.sort(rng.choice(Z_fit.shape[0], fit_limit, replace=False))
            Z_model_fit = Z_fit[model_rows]
        else:
            Z_model_fit = Z_fit
        estimator.fit(Z_model_fit)
        # sklearn novelty estimators return larger scores for more-normal rows.
        cal_scores = estimator.score_samples(Z_cal)
        val_scores = estimator.score_samples(Z_val)
        thresholds = []
        for target_fpr in DEFAULT_FPRS:
            threshold = float(np.quantile(cal_scores, target_fpr))
            pred = (val_scores < threshold).astype(int)
            thresholds.append(_metric_row(y_val, pred, target_fpr, threshold, name))
        eligible = [
            row for row in thresholds
            if row["validation_fpr"] is not None
            and row["validation_fpr"] <= max_validation_fpr
        ]
        # If distribution shift means no calibrated point meets the observed
        # validation FPR cap, choose the lowest-FPR point and make that failure
        # explicit in the report rather than silently relaxing the cap.
        selection_pool = eligible or thresholds
        best = max(
            selection_pool,
            key=lambda row: (
                -row["validation_fpr"] if not eligible else row["validation_recall"],
                row["validation_f1"],
                row["validation_precision"],
            ),
        )
        model_results.append({
            "model": name,
            "model_fit_normal_rows": int(Z_model_fit.shape[0]),
            "validation_roc_auc": float(roc_auc_score(y_val, -val_scores)),
            "threshold_sweep": thresholds,
            "selected_validation_operating_point": best,
            "selection_rule": (
                "highest training-validation recall among points meeting max_validation_fpr; "
                "ties prefer F1 then precision; if none qualify, choose the lowest observed validation FPR"
            ),
            "max_validation_fpr": max_validation_fpr,
            "validation_fpr_cap_met": bool(best["validation_fpr"] <= max_validation_fpr),
        })
        fitted[name] = estimator

    # Permutation importance is computed only on the training-partition
    # validation set. It measures change in validation ROC-AUC after shuffling
    # each original feature; it is not a causal explanation.
    if_model = fitted["isolation_forest"]
    base_scores = -if_model.score_samples(Z_val)
    base_auc = float(roc_auc_score(y_val, base_scores))
    feature_importance = []
    val_frame = X_all.iloc[val_idx].reset_index(drop=True)
    for column in X_all.columns:
        drops = []
        for repeat in range(permutation_repeats):
            permuted = val_frame.copy()
            values = permuted[column].to_numpy(copy=True)
            rng.shuffle(values)
            permuted[column] = values
            transformed = preprocessor.transform(permuted)
            shuffled_auc = float(roc_auc_score(
                y_val, -if_model.score_samples(transformed)
            ))
            drops.append(base_auc - shuffled_auc)
        feature_importance.append({
            "feature": str(column),
            "mean_roc_auc_drop": float(np.mean(drops)),
            "std_roc_auc_drop": float(np.std(drops)),
            "repeats": permutation_repeats,
        })
    feature_importance.sort(key=lambda item: item["mean_roc_auc_drop"], reverse=True)

    report = {
        "benchmark": "UNSW-NB15",
        "experiment": "training-partition model comparison and threshold sensitivity",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "data": {
            "training_file": str(train_path),
            "training_sha256": sha256_file(train_path),
            "official_training_rows": int(len(frame)),
            "normal_rows": int(len(normal_idx)),
            "attack_rows": int(len(attack_idx)),
            "fit_normal_rows": int(len(fit_idx)),
            "calibration_normal_rows": int(len(cal_idx)),
            "validation_normal_rows": int(np.sum(labels[val_idx] == 0)),
            "validation_attack_rows": int(np.sum(labels[val_idx] == 1)),
            "validation_rows": int(len(val_idx)),
            "official_test_file_loaded": False,
            "official_test_rows_used": 0,
        },
        "configuration": {
            "seed": seed,
            "max_fit_samples": max_fit_samples,
            "max_validation_samples": max_validation_samples,
            "per_model_fit_caps": per_model_fit_caps,
            "calibration_target_fprs": list(DEFAULT_FPRS),
            "permutation_repeats": permutation_repeats,
            "max_validation_fpr": max_validation_fpr,
        },
        "model_comparison": model_results,
        "isolation_forest_feature_permutation_importance": {
            "baseline_validation_roc_auc": base_auc,
            "interpretation": "Positive ROC-AUC drop means shuffling the feature reduced validation ranking performance; not causal attribution.",
            "features": feature_importance,
        },
        "integrity_notes": [
            "This experiment reads only the official training partition; it does not open the official test file.",
            "All attack-labeled training rows are excluded from fitting, preprocessing fitting, and threshold calibration.",
            "Thresholds are quantiles of a separate normal-only calibration subset.",
            "Labeled attack rows from the official training partition are used only for validation-based model/threshold selection.",
            "The official test partition must be evaluated once after selection is frozen.",
            "Scores are anomaly ranking scores, not probabilities or confidence values.",
            "LOF and One-Class SVM can be computationally expensive; sample caps are recorded for reproducibility.",
        ],
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "unsw_nb15_optimization.json"
    output_file.write_text(json.dumps(report, indent=2, allow_nan=False), encoding="utf-8")
    print(json.dumps({
        "output": str(output_file),
        "models": [
            item["selected_validation_operating_point"] for item in model_results
        ],
        "top_features": feature_importance[:10],
        "official_test_loaded": False,
    }, indent=2))
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train-csv", type=Path)
    parser.add_argument("--download-data", action="store_true",
                        help="Use the checksum-verifying downloader and its corrected training-file path")
    parser.add_argument("--data-dir", type=Path, default=Path("datasets/unsw_nb15"))
    parser.add_argument("--output-dir", type=Path, default=Path("results/unsw_nb15/optimization"))
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--validation-fraction", type=float, default=0.20)
    parser.add_argument("--max-fit-samples", type=int, default=15000)
    parser.add_argument("--max-validation-samples", type=int, default=12000)
    parser.add_argument("--permutation-repeats", type=int, default=2)
    parser.add_argument("--max-validation-fpr", type=float, default=0.10)
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.download_data:
        if args.train_csv:
            raise SystemExit("Use --download-data or --train-csv, not both.")
        from evaluation.run_unsw_nb15 import download_dataset
        train_csv, _ = download_dataset(args.data_dir)
    else:
        if not args.train_csv:
            raise SystemExit("Provide --train-csv or use --download-data.")
        train_csv = args.train_csv
    run_optimization(
        train_csv, args.output_dir, seed=args.seed,
        validation_fraction=args.validation_fraction,
        max_fit_samples=args.max_fit_samples,
        max_validation_samples=args.max_validation_samples,
        permutation_repeats=args.permutation_repeats,
        max_validation_fpr=args.max_validation_fpr,
    )
