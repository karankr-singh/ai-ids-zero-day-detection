"""Evaluate a saved live baseline against a separate benign capture and
clearly labeled synthetic attack profiles.

This is a mixed-source engineering benchmark, not a substitute for a public
labeled intrusion-detection dataset or controlled real-attack evaluation.
"""
import argparse
import json
import time
from pathlib import Path

from detector import AnomalyDetector
from simulator import AttackSimulator, ATTACK_PROFILES

FEATURE_FIELDS = {
    "packet_size", "inter_arrival_ms", "dst_port", "src_port", "flags",
    "ttl", "payload_entropy", "flow_duration_ms", "bytes_per_second",
    "timestamp", "protocol", "source",
}


def load_jsonl(path):
    records = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {line_number}: {exc}") from exc
            records.append({key: value for key, value in row.items()
                            if key in FEATURE_FIELDS})
    return records


def collect_benign_capture(interface, seconds, minimum):
    """Capture a separate operator-designated benign window; metadata only."""
    try:
        from scapy.all import sniff
        from live_capture import ScapyCapture
    except ImportError as exc:
        raise SystemExit("Scapy is required. Install dependencies first.") from exc

    adapter = ScapyCapture()
    records = []

    def on_packet(packet):
        record = adapter.to_record(packet)
        if record is not None and len(records) < 50000:
            records.append({
                key: value for key, value in record.items()
                if key not in {"src_ip", "dst_ip"}
            })

    sniff(iface=interface, prn=on_packet, store=False, timeout=seconds)
    if len(records) < minimum:
        raise SystemExit(
            f"Only {len(records)} test records captured; {minimum} required. "
            "Increase --normal-seconds."
        )
    return records


def calculate_metrics(y_true, y_pred):
    tp = sum(actual == 1 and predicted == 1
             for actual, predicted in zip(y_true, y_pred))
    tn = sum(actual == 0 and predicted == 0
             for actual, predicted in zip(y_true, y_pred))
    fp = sum(actual == 0 and predicted == 1
             for actual, predicted in zip(y_true, y_pred))
    fn = sum(actual == 1 and predicted == 0
             for actual, predicted in zip(y_true, y_pred))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if precision + recall else 0.0)
    fpr = fp / (fp + tn) if fp + tn else 0.0
    accuracy = (tp + tn) / max(tp + tn + fp + fn, 1)
    return {
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "precision": precision, "recall": recall,
        "f1": f1, "false_positive_rate": fpr, "accuracy": accuracy,
    }


def run_benchmark(baseline, benign_test, attacks_per_type=100):
    if not baseline:
        raise ValueError("Baseline file is empty")
    if not benign_test:
        raise ValueError("Independent benign test capture is empty")
    detector = AnomalyDetector(pretrain=False)
    calibration = detector.fit_live_baseline(baseline, min_samples=200)

    simulator = AttackSimulator()
    attack_records = []
    for attack_key in ATTACK_PROFILES:
        for record in simulator.inject_attack(attack_key, attacks_per_type):
            record["source"] = "live_capture"
            attack_records.append((attack_key, record))

    y_true, y_pred, latencies_ms = [], [], []
    per_attack = {key: {"detected": 0, "total": 0}
                  for key in ATTACK_PROFILES}

    for record in benign_test:
        record["source"] = "live_capture"
        start = time.perf_counter()
        prediction = detector.analyze(record)["is_anomaly"]
        latencies_ms.append((time.perf_counter() - start) * 1000)
        y_true.append(0)
        y_pred.append(int(prediction))

    for attack_key, record in attack_records:
        start = time.perf_counter()
        prediction = detector.analyze(record)["is_anomaly"]
        latencies_ms.append((time.perf_counter() - start) * 1000)
        y_true.append(1)
        y_pred.append(int(prediction))
        per_attack[attack_key]["total"] += 1
        per_attack[attack_key]["detected"] += int(prediction)

    metrics = calculate_metrics(y_true, y_pred)
    for counts in per_attack.values():
        counts["recall"] = (
            counts["detected"] / counts["total"] if counts["total"] else 0.0
        )

    ordered_latency = sorted(latencies_ms)
    return {
        "benchmark_type": "operator-designated benign capture + synthetic attacks",
        "baseline_samples": len(baseline),
        "calibration_samples": calibration["calibration_samples"],
        "benign_test_samples": len(benign_test),
        "synthetic_attack_samples": len(attack_records),
        "metrics": metrics,
        "per_attack": per_attack,
        "latency_ms": {
            "mean": sum(latencies_ms) / len(latencies_ms),
            "p95": ordered_latency[
                min(len(ordered_latency) - 1, int(0.95 * len(ordered_latency)))
            ],
        },
        "limitations": [
            "Attack records are generated from this repository's synthetic profiles.",
            "Benign test traffic is operator-designated, not independently labeled.",
            "Results do not establish real-world attack detection performance.",
            "Use an independently labeled dataset and controlled lab captures for external validation.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate AI-IDS against independent benign capture and synthetic attacks"
    )
    parser.add_argument("--baseline", default="logs/live_baseline.jsonl")
    parser.add_argument("--interface", required=True)
    parser.add_argument("--normal-seconds", type=int, default=30)
    parser.add_argument("--attacks-per-type", type=int, default=100)
    parser.add_argument("--min-normal-samples", type=int, default=200)
    parser.add_argument("--assume-benign", action="store_true",
                        help="Confirm the separate test capture is intended as benign traffic")
    parser.add_argument("--output", default="logs/benchmark_report.json")
    args = parser.parse_args()

    if not args.assume_benign:
        parser.error(
            "Pass --assume-benign only when the separate capture window is intended "
            "to contain benign traffic."
        )
    if args.normal_seconds < 1 or args.attacks_per_type < 1:
        parser.error("Capture duration and attacks per type must be positive")

    baseline = load_jsonl(args.baseline)
    print(f"Loaded {len(baseline)} saved baseline records.")
    print(f"Capturing a separate {args.normal_seconds}s benign test window...")
    benign_test = collect_benign_capture(
        args.interface, args.normal_seconds, args.min_normal_samples
    )
    print(f"Captured {len(benign_test)} test records.")
    result = run_benchmark(baseline, benign_test, args.attacks_per_type)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    print(f"\nBenchmark report saved to: {output}")


if __name__ == "__main__":
    main()
