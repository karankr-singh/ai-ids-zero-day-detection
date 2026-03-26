import json
import os
import time
from collections import deque, Counter
from pathlib import Path


class AlertLogger:
    """
    Stores security alerts in memory and optionally persists to disk.

    Usage:
        log = AlertLogger("logs/alerts.json")
        log.add(alert_dict)
        recent = log.recent(20)
        stats  = log.severity_counts()
    """

    def __init__(self, filepath: str = "logs/alerts.json", maxlen: int = 500):
        self._alerts  = deque(maxlen=maxlen)
        self._filepath = Path(filepath)
        self._filepath.parent.mkdir(parents=True, exist_ok=True)

    def add(self, alert: dict):
        self._alerts.append(alert)
        # Append to JSONL file
        try:
            with self._filepath.open("a") as f:
                f.write(json.dumps(alert) + "\n")
        except Exception:
            pass

    def recent(self, n: int = 50) -> list:
        return list(self._alerts)[-n:]

    def all(self) -> list:
        return list(self._alerts)

    def severity_counts(self) -> dict:
        c = Counter(a.get("severity", "LOW") for a in self._alerts)
        return {"CRITICAL": c["CRITICAL"], "HIGH": c["HIGH"],
                "MEDIUM":   c["MEDIUM"],   "LOW":  c["LOW"]}

    def threat_counts(self) -> dict:
        return dict(Counter(a.get("threat_type", "Unknown") for a in self._alerts))

    def clear(self):
        self._alerts.clear()
        try:
            self._filepath.write_text("")
        except Exception:
            pass

    def __len__(self):
        return len(self._alerts)
