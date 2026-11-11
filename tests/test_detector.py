import time

from detector import AnomalyDetector
from simulator import AttackSimulator


def normal_packet():
    return {
        "src_ip": "192.168.1.10",
        "dst_ip": "203.0.113.10",
        "src_port": 52344,
        "dst_port": 443,
        "protocol": "HTTPS",
        "packet_size": 520,
        "inter_arrival_ms": 18.0,
        "flags": 24,
        "ttl": 64,
        "payload_entropy": 4.1,
        "flow_duration_ms": 250.0,
        "bytes_per_second": 4000.0,
        "timestamp": time.time(),
        "pkt_type": "normal",
    }


def test_analyze_returns_score_without_fake_confidence_or_metrics():
    detector = AnomalyDetector()
    before = detector.stats["trusted_normal_samples"]

    result = detector.analyze(normal_packet())

    assert "anomaly_score" in result
    assert "confidence" not in result
    assert "accuracy" not in result
    assert "fpr" not in result
    assert "proposed_response" in result
    assert detector.stats["trusted_normal_samples"] == before


def test_only_explicitly_confirmed_normal_records_enter_training_buffer():
    detector = AnomalyDetector()
    packet = normal_packet()
    before = detector.stats["trusted_normal_samples"]

    assert detector.add_confirmed_normal(packet, confirmed=False) is False
    assert detector.stats["trusted_normal_samples"] == before

    assert detector.add_confirmed_normal(packet, confirmed=True) is True
    assert detector.stats["trusted_normal_samples"] == before + 1


def test_retraining_uses_trusted_buffer_and_reports_actual_retrain_count():
    detector = AnomalyDetector()
    before = detector.stats["retrain_count"]

    assert detector.retrain() is True
    assert detector.stats["retrain_count"] == before + 1


def test_simulator_marks_normal_records_for_demo_only_label_filter():
    simulator = AttackSimulator()
    packet = simulator._make_normal_pkt()

    assert packet["pkt_type"] == "normal"
    detector = AnomalyDetector()
    before = detector.stats["trusted_normal_samples"]
    assert detector.add_confirmed_normal(packet, confirmed=True) is True
    assert detector.stats["trusted_normal_samples"] == before + 1
