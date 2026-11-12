import numpy as np
import pandas as pd
import pytest

from evaluation.optimize_unsw_nb15 import _metric_row, _preprocessor


def test_preprocessor_handles_mixed_features_and_unseen_categories():
    fit = pd.DataFrame({"proto": ["tcp", "udp", "tcp"], "bytes": [1, 2, 3]})
    transform = _preprocessor(fit)
    encoded = transform.fit_transform(fit)
    unseen = transform.transform(pd.DataFrame({"proto": ["icmp"], "bytes": [4]}))
    assert encoded.shape[1] == unseen.shape[1]
    assert np.isfinite(unseen.toarray() if hasattr(unseen, "toarray") else unseen).all()


def test_metric_row_reports_actual_confusion_counts():
    y = np.array([0, 0, 1, 1])
    pred = np.array([0, 1, 1, 0])
    row = _metric_row(y, pred, 0.05, -0.2, "fixture")
    assert row["confusion_matrix"] == {"tn": 1, "fp": 1, "fn": 1, "tp": 1}
    assert row["validation_recall"] == 0.5
    assert row["validation_fpr"] == 0.5


def test_validation_fraction_is_validated(tmp_path):
    from evaluation.optimize_unsw_nb15 import run_optimization
    with pytest.raises(ValueError):
        run_optimization(tmp_path / "missing.csv", tmp_path, validation_fraction=0.5)
