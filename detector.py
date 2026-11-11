import random
import time
import threading
from collections import deque

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


# Severity is a presentation/triage heuristic, not a calibrated risk estimate.
SEVERITY_THRESHOLDS = {
    "CRITICAL": -0.55,
    "HIGH": -0.40,
    "MEDIUM": -0.25,
    "LOW": -0.10,
}

PROPOSED_RESPONSES = {
    "CRITICAL": "Proposed: isolate host and escalate to SOC",
    "HIGH": "Proposed: review source and firewall policy",
    "MEDIUM": "Proposed: rate-limit candidate traffic and investigate",
    "LOW": "Proposed: log event and continue monitoring",
}


class AnomalyDetector:
    """Isolation Forest detector with an explicitly trusted-normal training buffer.

    The built-in baseline is synthetic and is suitable only for demonstrating the
    pipeline. It is not a validated model of an enterprise network.
    """

    def __init__(self, n_estimators: int = 150, contamination: float | str = "auto"):
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.model = self._new_model()
        self.scaler = StandardScaler()
        self._trusted_normal_buf = deque(maxlen=5000)
        self._model_lock = threading.RLock()
        self._is_trained = False
        self._stats = {
            "total_analyzed": 0,
            "total_anomalies": 0,
            "by_protocol": {},
            "trusted_normal_samples": 0,
            "retrain_count": 0,
        }
        self._pretrain()

    def _new_model(self):
        return IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=42,
            max_samples="auto",
        )

    def _extract_features(self, pkt: dict) -> np.ndarray:
        """Convert a packet/record into the current 10-feature prototype vector."""
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
        """Create a synthetic normal-only baseline for the demonstration."""
        normal = []
        for _ in range(800):
            pkt = {
                "packet_size": max(40, random.gauss(512, 180)),
                "inter_arrival_ms": max(0.5, random.gauss(20, 8)),
                "dst_port": random.choice([80, 443, 22, 8080, 3306, 53]),
                "src_port": random.randint(1024, 65535),
                "flags": random.choice([2, 18, 16, 24]),
                "ttl": random.randint(55, 70),
                "payload_entropy": max(0, random.gauss(4.2, 0.6)),
                "flow_duration_ms": max(10, random.gauss(300, 100)),
                "bytes_per_second": max(100, random.gauss(5000, 1500)),
                "timestamp": time.time(),
            }
            normal.append(self._extract_features(pkt))

        self._trusted_normal_buf.extend(normal)
        self._fit_on_trusted_normals()
        self._is_trained = True

    def _fit_on_trusted_normals(self):
        """Fit candidate preprocessing/model objects before swapping them in."""
        with self._model_lock:
            return self._fit_locked()

    def _fit_locked(self):
        X = np.asarray(self._trusted_normal_buf, dtype=float)
        if len(X) < 2:
            return False

        candidate_scaler = StandardScaler()
        X_scaled = candidate_scaler.fit_transform(X)
        candidate_model = self._new_model()
        candidate_model.fit(X_scaled)

        # Swap only after both fit operations succeed.
        self.scaler = candidate_scaler
        self.model = candidate_model
        self._is_trained = True
        self._stats["trusted_normal_samples"] = len(X)
        return True

    def add_confirmed_normal(self, pkt: dict, *, confirmed: bool = False) -> bool:
        """Add a record only when its normal label is independently trusted.

        Simulator labels can be used in the demo. A live capture must not call
        this method merely because the detector predicted 'normal'.
        """
        if not confirmed:
            return False
        with self._model_lock:
            self._trusted_normal_buf.append(self._extract_features(pkt))
            self._stats["trusted_normal_samples"] = len(self._trusted_normal_buf)
        return True

    def analyze(self, pkt: dict) -> dict:
        """Score one record; this method never adds traffic to the training set."""
        if not self._is_trained:
            raise RuntimeError("Detector has not been trained")

        feat = self._extract_features(pkt)
        with self._model_lock:
            X = self.scaler.transform([feat])
            score = float(self.model.score_samples(X)[0])
            pred = int(self.model.predict(X)[0])
        is_anomaly = pred == -1

        severity = "NORMAL"
        if is_anomaly:
            if score < SEVERITY_THRESHOLDS["CRITICAL"]:
                severity = "CRITICAL"
            elif score < SEVERITY_THRESHOLDS["HIGH"]:
                severity = "HIGH"
            elif score < SEVERITY_THRESHOLDS["MEDIUM"]:
                severity = "MEDIUM"
            else:
                severity = "LOW"

        threat_type = self._classify_threat(pkt, score) if is_anomaly else "—"
        proposed_response = (
            PROPOSED_RESPONSES.get(severity, "Proposed: investigate")
            if is_anomaly else "No response proposed"
        )

        with self._model_lock:
            self._stats["total_analyzed"] += 1
            if is_anomaly:
                self._stats["total_anomalies"] += 1
            proto = pkt.get("protocol", "UNKNOWN")
            self._stats["by_protocol"][proto] = self._stats["by_protocol"].get(proto, 0) + 1

        return {
            "is_anomaly": is_anomaly,
            "anomaly_score": round(score, 4),
            "severity": severity,
            "threat_type": threat_type,
            "response_action": proposed_response,
        }

    def _classify_threat(self, pkt: dict, score: float) -> str:
        """Heuristic labels for the demo; these do not establish attack attribution."""
        port = pkt.get("dst_port", 0)
        size = pkt.get("packet_size", 0)
        entropy = pkt.get("payload_entropy", 4.0)
        inter = pkt.get("inter_arrival_ms", 20)
        flags = pkt.get("flags", 2)

        if flags == 0:
            return "NULL / Malformed Packet"
        if inter < 5 and port > 1024:
            return "Port Scan"
        if inter < 3 and size < 120:
            return "DDoS-like Traffic"
        if size > 1400 and entropy > 7.0:
            return "Possible Data Exfiltration"
        if inter < 8 and port in [22, 3389, 21, 23]:
            return "Possible Brute Force"
        if entropy > 7.4 and 8 < inter < 15:
            return "Possible Encrypted C2"
        return "Unknown Anomaly"

    def retrain(self) -> bool:
        """Refit only on trusted-normal samples; never on detector predictions."""
        with self._model_lock:
            if len(self._trusted_normal_buf) < 200:
                return False
            if not self._fit_locked():
                return False
            self._stats["retrain_count"] += 1
            return True

    @property
    def training_status(self) -> str:
        return "synthetic baseline (not independently evaluated)" if self._is_trained else "untrained"

    @property
    def stats(self) -> dict:
        with self._model_lock:
            return {
                **self._stats,
                "by_protocol": dict(self._stats["by_protocol"]),
            }
