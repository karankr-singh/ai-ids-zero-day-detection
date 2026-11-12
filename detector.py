import random
import time
import threading
from collections import deque

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


SEVERITY_THRESHOLDS = {
    "CRITICAL": -0.55,
    "HIGH": -0.40,
    "MEDIUM": -0.25,
    "LOW": -0.10,
}

PROPOSED_RESPONSES = {
    "CRITICAL": "Proposed: escalate for analyst review",
    "HIGH": "Proposed: inspect source and destination",
    "MEDIUM": "Proposed: review candidate traffic",
    "LOW": "Proposed: log candidate and continue monitoring",
}


class AnomalyDetector:
    """Isolation Forest detector with separate synthetic and live baselines.

    Live learning samples are collected only during an explicit operator-selected
    window. The detector never labels its own predictions as trusted normal data.
    A live baseline is calibrated on a held-out slice of that window, but the
    window itself is not independently proven attack-free.
    """

    def __init__(
        self,
        n_estimators: int = 150,
        contamination: float | str = "auto",
        pretrain: bool = True,
        calibration_rate: float = 0.01,
    ):
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.calibration_rate = calibration_rate
        self.model = self._new_model()
        self.scaler = StandardScaler()
        self._trusted_normal_buf = deque(maxlen=5000)
        self._model_lock = threading.RLock()
        self._is_trained = False
        self._baseline_mode = "untrained"
        self._decision_threshold = None
        self._calibration_samples = 0
        self._stats = {
            "total_analyzed": 0,
            "total_anomalies": 0,
            "by_protocol": {},
            "trusted_normal_samples": 0,
            "retrain_count": 0,
        }
        if pretrain:
            self._pretrain()

    def _new_model(self):
        return IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=42,
            max_samples="auto",
        )

    def _extract_features(self, pkt: dict) -> np.ndarray:
        hour = int(pkt.get("timestamp", time.time()) % 86400 // 3600)
        return np.array([
            pkt.get("packet_size", 0),
            pkt.get("inter_arrival_ms", 0),
            pkt.get("dst_port", 0),
            pkt.get("src_port", 0),
            pkt.get("flags", 0),
            pkt.get("ttl", 64),
            pkt.get("payload_entropy", 0.0),
            pkt.get("flow_duration_ms", 0),
            pkt.get("bytes_per_second", 0),
            hour,
        ], dtype=float)

    def _pretrain(self):
        """Create the synthetic normal-only baseline used by simulator mode."""
        rng = random.Random(42)
        normal = []
        for _ in range(800):
            pkt = {
                "packet_size": max(40, rng.gauss(512, 180)),
                "inter_arrival_ms": max(0.5, rng.gauss(20, 8)),
                "dst_port": rng.choice([80, 443, 22, 8080, 3306, 53]),
                "src_port": rng.randint(1024, 65535),
                "flags": rng.choice([2, 18, 16, 24]),
                "ttl": rng.randint(55, 70),
                "payload_entropy": max(0, rng.gauss(4.2, 0.6)),
                "flow_duration_ms": max(10, rng.gauss(300, 100)),
                "bytes_per_second": max(100, rng.gauss(5000, 1500)),
                "timestamp": time.time(),
            }
            normal.append(self._extract_features(pkt))

        with self._model_lock:
            self._trusted_normal_buf.extend(normal)
            self._fit_synthetic_locked()

    def _fit_synthetic_locked(self):
        X = np.asarray(self._trusted_normal_buf, dtype=float)
        candidate_scaler = StandardScaler()
        X_scaled = candidate_scaler.fit_transform(X)
        candidate_model = self._new_model()
        candidate_model.fit(X_scaled)
        self.scaler = candidate_scaler
        self.model = candidate_model
        self._decision_threshold = float(candidate_model.offset_)
        self._is_trained = True
        self._baseline_mode = "synthetic"
        self._stats["trusted_normal_samples"] = len(X)

    def fit_live_baseline(self, records: list[dict], min_samples: int = 200) -> dict:
        """Train on operator-designated normal-window records and calibrate on holdout.

        The final 20% is held out from fitting. Its low-tail score quantile sets
        the anomaly threshold; it is not an independent attack evaluation.
        """
        if len(records) < min_samples:
            raise ValueError(
                f"Need at least {min_samples} learning records; received {len(records)}"
            )
        X = np.asarray([self._extract_features(row) for row in records], dtype=float)
        if X.ndim != 2 or X.shape[1] != 10 or not np.isfinite(X).all():
            raise ValueError("Learning data contains invalid or non-finite features")

        rng = np.random.default_rng(42)
        indices = rng.permutation(len(X))
        split = int(len(X) * 0.8)
        train_idx, calibration_idx = indices[:split], indices[split:]
        if len(calibration_idx) < 30:
            raise ValueError("Not enough held-out records for threshold calibration")

        candidate_scaler = StandardScaler()
        X_train = candidate_scaler.fit_transform(X[train_idx])
        X_calibration = candidate_scaler.transform(X[calibration_idx])
        candidate_model = self._new_model()
        candidate_model.fit(X_train)

        calibration_scores = candidate_model.score_samples(X_calibration)
        threshold = float(np.quantile(
            calibration_scores, self.calibration_rate, method="linear"
        ))

        # Atomic swap: capture never sees a partially fitted model.
        with self._model_lock:
            self.scaler = candidate_scaler
            self.model = candidate_model
            self._decision_threshold = threshold
            self._is_trained = True
            self._baseline_mode = "live"
            self._calibration_samples = len(calibration_idx)
            self._trusted_normal_buf.clear()
            self._trusted_normal_buf.extend(X)
            self._stats["trusted_normal_samples"] = len(X)
            self._stats["retrain_count"] = 0

        return {
            "training_samples": len(train_idx),
            "calibration_samples": len(calibration_idx),
            "threshold": threshold,
            "target_calibration_tail": self.calibration_rate,
        }

    def add_confirmed_normal(self, pkt: dict, *, confirmed: bool = False) -> bool:
        """Append only independently trusted labels (used by simulator mode)."""
        if not confirmed:
            return False
        with self._model_lock:
            self._trusted_normal_buf.append(self._extract_features(pkt))
            self._stats["trusted_normal_samples"] = len(self._trusted_normal_buf)
        return True

    def analyze(self, pkt: dict) -> dict:
        if not self._is_trained or self._decision_threshold is None:
            raise RuntimeError("Detector has no trained and calibrated baseline")

        feat = self._extract_features(pkt)
        with self._model_lock:
            X = self.scaler.transform([feat])
            score = float(self.model.score_samples(X)[0])
            is_anomaly = score < self._decision_threshold

        live_record = pkt.get("source") == "live_capture"
        if is_anomaly and live_record:
            # Live severity is deliberately unranked: score distance is not a
            # calibrated measure of attack impact or incident severity.
            severity = "LOW"
            threat_type = "Unclassified anomaly candidate"
            proposed_response = "Proposed: review candidate; no automated response"
        elif is_anomaly:
            severity = "LOW"
            if score < SEVERITY_THRESHOLDS["CRITICAL"]:
                severity = "CRITICAL"
            elif score < SEVERITY_THRESHOLDS["HIGH"]:
                severity = "HIGH"
            elif score < SEVERITY_THRESHOLDS["MEDIUM"]:
                severity = "MEDIUM"
            threat_type = self._classify_threat(pkt, score)
            proposed_response = PROPOSED_RESPONSES.get(
                severity, "Proposed: investigate"
            )
        else:
            severity = "NORMAL"
            threat_type = "—"
            proposed_response = "No response proposed"

        with self._model_lock:
            self._stats["total_analyzed"] += 1
            if is_anomaly:
                self._stats["total_anomalies"] += 1
            proto = str(pkt.get("protocol", "UNKNOWN"))
            self._stats["by_protocol"][proto] = (
                self._stats["by_protocol"].get(proto, 0) + 1
            )

        return {
            "is_anomaly": is_anomaly,
            "anomaly_score": round(score, 6),
            "severity": severity,
            "threat_type": threat_type,
            "proposed_response": proposed_response,
            "decision_threshold": round(self._decision_threshold, 6),
            "baseline_mode": self._baseline_mode,
        }

    def _classify_threat(self, pkt: dict, score: float) -> str:
        """Simulator-only heuristic labels; not verified attack attribution."""
        port = pkt.get("dst_port", 0)
        size = pkt.get("packet_size", 0)
        entropy = pkt.get("payload_entropy", 4.0)
        inter = pkt.get("inter_arrival_ms", 20)
        flags = pkt.get("flags", 2)

        if pkt.get("protocol") == "TCP" and flags == 0:
            return "TCP NULL-flag Packet (heuristic)"
        if inter < 5 and port > 1024:
            return "Port Scan (heuristic)"
        if inter < 3 and size < 120:
            return "DDoS-like Traffic (heuristic)"
        if size > 1400 and entropy > 7.0:
            return "Possible Data Exfiltration (heuristic)"
        if inter < 8 and port in [22, 3389, 21, 23]:
            return "Possible Brute Force (heuristic)"
        if entropy > 7.4 and 8 < inter < 15:
            return "Possible Encrypted C2 (heuristic)"
        return "Unknown Anomaly"

    def retrain(self) -> bool:
        """Refit simulator trusted samples only; live calibration is explicit."""
        with self._model_lock:
            if self._baseline_mode != "synthetic" or len(self._trusted_normal_buf) < 200:
                return False
            self._fit_synthetic_locked()
            self._stats["retrain_count"] += 1
            return True

    @property
    def training_status(self) -> str:
        if self._baseline_mode == "live":
            return (
                f"live learning window; {self._stats['trusted_normal_samples']} "
                f"operator-designated samples; calibration holdout "
                f"{self._calibration_samples}; attack-free status unverified"
            )
        if self._baseline_mode == "synthetic":
            return "synthetic/simulator-labeled normals; not independently evaluated"
        return "untrained — live alerts disabled"

    @property
    def stats(self) -> dict:
        with self._model_lock:
            return {
                **self._stats,
                "by_protocol": dict(self._stats["by_protocol"]),
            }
