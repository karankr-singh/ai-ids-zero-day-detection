"""Held-out attack-category evaluation for UNSW-NB15.

The model and threshold are fitted using normal-labeled training records only.
Attack-category labels are used only to select and report the untouched test
records; they are never model features or training targets.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, confusion_matrix, f1_score, precision_score,
    recall_score, roc_auc_score,
)
from sklearn.model_selection import train_test_split

from evaluation.run_unsw_nb15 import (
    CATEGORY_COLUMN, DEFAULT_SEED, binary_labels, feature_frame,
    load_dataset, make_pipeline, sha256_file,
)


def evaluate_unseen_categories(
    train_path: Path,
    test_path: Path,
    output_dir: Path,
    *,
    categories: list[str] | None = None,
    seed: int = DEFAULT_SEED,
    validation_fraction: float = 0.20,
    target_fpr: float = 0.05,
    estimators: int = 200,
) -> dict:
    if not 0 < validation_fraction < 1:
        raise ValueError("validation_fraction must be between 0 and 1.")
    if not 0 < target_fpr < 1:
        raise ValueError("target_fpr must be between 0 and 1.")
    if estimators < 1:
        raise ValueError("estimators must be positive.")

    train = load_dataset(train_path)
    test = load_dataset(test_path)
    if CATEGORY_COLUMN not in train.columns or CATEGORY_COLUMN not in test.columns:
        raise ValueError("Both files must contain the attack_cat column for category holdout.")

    y_train = binary_labels(train, "training data")
    y_test_all = binary_labels(test, "test data")
    normal_train = feature_frame(train.loc[y_train == 0].reset_index(drop=True))
    if len(normal_train) < 10:
        raise ValueError("At least 10 normal training rows are required.")

    X_fit, X_cal = train_test_split(
        normal_train, test_size=validation_fraction, random_state=seed, shuffle=True
    )
    pipeline = make_pipeline(X_fit, estimators, seed)
    pipeline.fit(X_fit)

    calibration_scores = pipeline.score_samples(X_cal)
    threshold = float(np.quantile(calibration_scores, target_fpr))

    category_values = test[CATEGORY_COLUMN].fillna("Unknown").astype(str).str.strip()
    available = sorted(
        category_values.loc[y_test_all == 1].unique().tolist()
    )
    if not available:
        raise ValueError("No attack-labeled test records with attack categories were found.")

    if categories:
        requested = [value.strip() for value in categories if value.strip()]
        lookup = {value.casefold(): value for value in available}
        missing = [value for value in requested if value.casefold() not in lookup]
        if missing:
            raise ValueError(
                "Requested categories are absent from the labeled test split: "
                + ", ".join(missing)
                + ". Available: " + ", ".join(available)
            )
        selected = [lookup[value.casefold()] for value in requested]
    else:
        selected = available

    selected_attack_mask = (y_test_all == 1) & category_values.isin(selected).to_numpy()
    normal_test_mask = y_test_all == 0
    evaluation_mask = normal_test_mask | selected_attack_mask
    y_true = y_test_all[evaluation_mask]
    X_test = feature_frame(test.loc[evaluation_mask].reset_index(drop=True))
    X_test = X_test.reindex(columns=normal_train.columns)

    scores = pipeline.score_samples(X_test)
    predictions = (scores < threshold).astype(int)
    rank_scores = -scores
    tn, fp, fn, tp = confusion_matrix(y_true, predictions, labels=[0, 1]).ravel()

    per_category = {}
    selected_values = category_values.loc[evaluation_mask].reset_index(drop=True)
    for category in selected:
        mask = (selected_values.to_numpy() == category) & (y_true == 1)
        count = int(mask.sum())
        if count:
            detected = int(np.sum(predictions[mask] == 1))
            per_category[category] = {
                "attack_records": count,
                "detected": detected,
                "missed": count - detected,
                "recall": float(detected / count),
            }

    metrics = {
        "roc_auc": float(roc_auc_score(y_true, rank_scores)) if len(np.unique(y_true)) == 2 else None,
        "accuracy": float(accuracy_score(y_true, predictions)),
        "precision": float(precision_score(y_true, predictions, zero_division=0)),
        "recall": float(recall_score(y_true, predictions, zero_division=0)),
        "f1": float(f1_score(y_true, predictions, zero_division=0)),
        "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) else None,
        "false_negative_rate": float(fn / (fn + tp)) if (fn + tp) else None,
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }

    report = {
        "benchmark": "UNSW-NB15",
        "evaluation_type": "held-out attack-category detection",
        "evaluation_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "model": "sklearn.ensemble.IsolationForest",
        "metrics_on_normal_plus_selected_unseen_attacks": metrics,
        "per_unseen_attack_category": per_category,
        "holdout": {
            "selected_categories": selected,
            "selection_source": "attack_cat labels in official test file only",
            "all attack-labeled training records_excluded": True,
            "attack_category_labels_used_as_features": False,
            "test_normal_records": int(normal_test_mask.sum()),
            "test_selected_attack_records": int(selected_attack_mask.sum()),
            "test_excluded_attack_records": int((y_test_all == 1).sum() - selected_attack_mask.sum()),
            "available_test_attack_categories": available,
        },
        "training": {
            "official_training_rows": int(len(train)),
            "normal_training_rows": int(len(normal_train)),
            "fit_normal_rows": int(len(X_fit)),
            "calibration_normal_rows": int(len(X_cal)),
            "attack_training_rows_excluded": int(np.sum(y_train == 1)),
            "threshold": threshold,
            "target_calibration_tail_fraction": target_fpr,
            "random_seed": seed,
            "n_estimators": estimators,
        },
        "data_integrity": {
            "training_sha256": sha256_file(train_path),
            "test_sha256": sha256_file(test_path),
            "training_file": str(train_path),
            "test_file": str(test_path),
        },
        "interpretation": [
            "The detector is trained only on normal-labeled training records.",
            "All attack-labeled training records are excluded from fitting and calibration.",
            "Attack-category labels are used only to select and report test rows, never as features.",
            "The official test file is not used for fitting or threshold selection.",
            "This is an offline benchmark experiment, not proof of production zero-day detection.",
            "Isolation Forest scores are ranking scores, not probabilities.",
        ],
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "unsw_nb15_unseen_categories.json"
    output_file.write_text(json.dumps(report, indent=2, allow_nan=False), encoding="utf-8")
    print(json.dumps({
        "output": str(output_file),
        "selected_categories": selected,
        "metrics": metrics,
        "per_category": per_category,
        "fit_normal_rows": len(X_fit),
        "calibration_normal_rows": len(X_cal),
        "test_normal_rows": int(normal_test_mask.sum()),
        "test_selected_attack_rows": int(selected_attack_mask.sum()),
        "threshold": threshold,
    }, indent=2))
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train-csv", type=Path)
    parser.add_argument("--test-csv", type=Path)
    parser.add_argument("--download-data", action="store_true")
    parser.add_argument("--data-dir", type=Path, default=Path("datasets/unsw_nb15"))
    parser.add_argument("--force-download", action="store_true")
    parser.add_argument("--output-dir", type=Path, default=Path("results/unsw_nb15"))
    parser.add_argument("--categories", help="Comma-separated attack_cat values; default evaluates every attack category in the test split.")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--validation-fraction", type=float, default=0.20)
    parser.add_argument("--target-fpr", type=float, default=0.05)
    parser.add_argument("--estimators", type=int, default=200)
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.download_data:
        if args.train_csv or args.test_csv:
            raise SystemExit("Use --download-data or explicit CSV paths, not both.")
        from evaluation.run_unsw_nb15 import download_dataset
        train_csv, test_csv = download_dataset(args.data_dir, force=args.force_download)
    else:
        if not args.train_csv or not args.test_csv:
            raise SystemExit("Provide --train-csv and --test-csv, or use --download-data.")
        train_csv, test_csv = args.train_csv, args.test_csv
    requested_categories = (
        [item.strip() for item in args.categories.split(",") if item.strip()]
        if args.categories else None
    )
    evaluate_unseen_categories(
        train_csv, test_csv, args.output_dir,
        categories=requested_categories,
        seed=args.seed,
        validation_fraction=args.validation_fraction,
        target_fpr=args.target_fpr,
        estimators=args.estimators,
    )
