import random
import unittest

from detector import AnomalyDetector


def make_normal_records(count=500):
    rng = random.Random(7)
    now = 1_800_000_000.0
    records = []
    for index in range(count):
        records.append({
            "packet_size": max(60, rng.gauss(700, 90)),
            "inter_arrival_ms": max(1, rng.gauss(35, 8)),
            "dst_port": rng.choice([53, 80, 443]),
            "src_port": rng.randint(40000, 65000),
            "flags": rng.choice([2, 16, 18]),
            "ttl": rng.randint(58, 66),
            "payload_entropy": max(0, rng.gauss(4.5, 0.4)),
            "flow_duration_ms": max(1, rng.gauss(250, 40)),
            "bytes_per_second": max(1, rng.gauss(7000, 800)),
            "timestamp": now + index * 0.01,
            "protocol": "TCP",
            "source": "live_capture",
        })
    return records


class LiveBaselineTests(unittest.TestCase):
    def test_live_detector_starts_untrained(self):
        detector = AnomalyDetector(pretrain=False)
        self.assertIn("untrained", detector.training_status)
        with self.assertRaises(RuntimeError):
            detector.analyze(make_normal_records(1)[0])

    def test_live_training_requires_minimum_samples(self):
        detector = AnomalyDetector(pretrain=False)
        with self.assertRaises(ValueError):
            detector.fit_live_baseline(make_normal_records(99), min_samples=100)

    def test_live_baseline_calibrates_and_scores(self):
        detector = AnomalyDetector(pretrain=False)
        result = detector.fit_live_baseline(make_normal_records(), min_samples=200)
        self.assertGreater(result["training_samples"], 0)
        self.assertGreater(result["calibration_samples"], 0)
        self.assertEqual(detector.stats["trusted_normal_samples"], 500)
        score = detector.analyze(make_normal_records(1)[0])
        self.assertEqual(score["baseline_mode"], "live")
        self.assertEqual(score["severity"], "LOW" if score["is_anomaly"] else "NORMAL")
        self.assertEqual(
            score["threat_type"],
            "Unclassified anomaly candidate" if score["is_anomaly"] else "—",
        )

    def test_predictions_are_not_added_to_training_buffer(self):
        detector = AnomalyDetector(pretrain=False)
        detector.fit_live_baseline(make_normal_records(), min_samples=200)
        before = detector.stats["trusted_normal_samples"]
        detector.analyze(make_normal_records(1)[0])
        self.assertEqual(detector.stats["trusted_normal_samples"], before)


if __name__ == "__main__":
    unittest.main()
