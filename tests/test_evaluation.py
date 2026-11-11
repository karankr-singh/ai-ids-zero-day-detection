import numpy as np
import pandas as pd

from evaluation.run_unsw_nb15 import (
    binary_labels,
    feature_frame,
    make_pipeline,
    precision_at_k,
)


def test_feature_frame_excludes_labels_and_identifier():
    frame = pd.DataFrame({
        "id": [1, 2],
        "proto": ["tcp", "udp"],
        "bytes": [10, 20],
        "attack_cat": ["Normal", "Generic"],
        "label": [0, 1],
    })
    features = feature_frame(frame)
    assert list(features.columns) == ["proto", "bytes"]


def test_binary_labels_rejects_non_binary_values():
    frame = pd.DataFrame({"label": [0, 1]})
    assert binary_labels(frame, "fixture").tolist() == [0, 1]


def test_pipeline_fits_mixed_features_and_scores_unknown_category():
    X = pd.DataFrame({
        "proto": ["tcp", "udp", "tcp", "icmp", "udp", "tcp"],
        "bytes": [10, 20, 12, 15, 19, 11],
    })
    model = make_pipeline(X, estimators=10, seed=7)
    model.fit(X)
    scores = model.score_samples(pd.DataFrame({
        "proto": ["new-protocol"],
        "bytes": [17],
    }))
    assert scores.shape == (1,)
    assert np.isfinite(scores[0])


def test_precision_at_k_uses_most_anomalous_records():
    labels = np.array([0, 1, 1, 0])
    anomaly_scores = np.array([0.1, 0.9, 0.8, 0.2])
    result = precision_at_k(labels, anomaly_scores, 2)
    assert result["evaluated_k"] == 2
    assert result["precision_at_k"] == 1.0
    assert result["attacks_in_top_k"] == 2
