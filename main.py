import argparse
import json
from pathlib import Path
import signal
import time
import threading

from detector import AnomalyDetector
from simulator import AttackSimulator, ATTACK_PROFILES
from llm_engine import LLMEngine
from logger import AlertLogger
from dashboard import Dashboard
from report import generate_report

_running = True
_alert_id = 0

detector = AnomalyDetector()
simulator = AttackSimulator()
llm = LLMEngine()
log = AlertLogger("logs/alerts.json")
dash = None


def _on_exit(sig, frame):
    global _running
    _running = False


signal.signal(signal.SIGINT, _on_exit)


def _handle_record(pkt):
    """Run one simulator or live-capture record through the common pipeline."""
    global _alert_id
    result = detector.analyze(pkt)
    if pkt.get("pkt_type") in ATTACK_PROFILES:
        dash.record_scenario_record(pkt, result["is_anomaly"])
    if result["is_anomaly"]:
        _alert_id += 1
        analysis = llm.analyze(pkt, result) if pkt.get("source") != "live_capture" else (
            "Unclassified statistical outlier against the learned local baseline. "
            "This is a candidate for review, not a confirmed attack."
        )
        alert = _build_alert(_alert_id, pkt, result, analysis)
        log.add(alert)
        dash.add_alert(alert)
    else:
        dash.add_normal_tick()

    stats = detector.stats
    dash.update_stats({
        "packets": stats["total_analyzed"],
        "alerts": stats["total_anomalies"],
        "training_status": detector.training_status,
        "monitoring": True,
        "mode": "PASSIVE LIVE" if pkt.get("source") == "live_capture" else "SIMULATOR DEMO",
        "phase": "monitoring",
    })


def simulator_loop(packets_per_second=5):
    """Generate synthetic records; simulator labels are trusted only here."""
    interval = 1.0 / packets_per_second
    while _running:
        pkt = simulator.generate_packet()
        detector.add_confirmed_normal(
            pkt, confirmed=(pkt.get("pkt_type") == "normal")
        )
        _handle_record(pkt)
        time.sleep(interval)


def inject_attack(attack_key, count=15, delay=2.0):
    time.sleep(delay)
    if not _running:
        return
    profile = ATTACK_PROFILES[attack_key]
    dash.update_scenario({
        "status": "RUNNING",
        "key": attack_key,
        "label": profile["label"],
        "description": profile["description"],
        "target": count,
        "generated": 0,
        "candidates": 0,
    })
    dash.log_system(
        f"Starting simulated scenario: {profile['label']} ({count} records)",
        "yellow",
    )
    for pkt in simulator.inject_attack(attack_key, count):
        _handle_record(pkt)
        time.sleep(0.05)
    dash.update_scenario({"status": "COMPLETE"})
    dash.log_system(f"Scenario complete: {profile['label']}", "green")


def demo_mode(duration=32, count=12):
    """Run a short, repeatable four-scenario sequence for screen recording."""
    attacks = [
        (2, "port_scan"),
        (9, "ddos"),
        (16, "data_exfiltration"),
        (23, "brute_force"),
    ]
    for delay, key in attacks:
        threading.Thread(
            target=inject_attack, args=(key, count, delay), daemon=True
        ).start()

    def stop_demo():
        global _running
        time.sleep(duration)
        _running = False

    threading.Thread(target=stop_demo, daemon=True).start()


def live_capture_loop(interface=None, bpf_filter=None,
                      learn_seconds=30, min_training_samples=200):
    """Learn from an operator-designated quiet window, then passively monitor."""
    try:
        from scapy.all import sniff
    except ImportError as exc:
        raise SystemExit(
            "Scapy is required for live capture. Install it with: pip install scapy"
        ) from exc

    from live_capture import ScapyCapture

    global detector
    detector = AnomalyDetector(pretrain=False)
    adapter = ScapyCapture()
    learning_records = []

    dash.log_system("PASSIVE LEARNING MODE — no anomaly alerts are generated", "cyan")
    dash.log_system(
        f"Keep this network quiet for {learn_seconds}s; avoid downloads, "
        "streaming, scans, and other unusual activity.",
        "yellow",
    )
    dash.log_system(
        f"Interface: {interface or 'Scapy default'} | BPF: {bpf_filter or 'none'}",
        "cyan",
    )
    dash.update_stats({
        "training_status": "collecting operator-designated normal traffic",
        "monitoring": False,
        "mode": "PASSIVE LIVE",
        "phase": "learning",
    })

    def collect_packet(packet):
        if not _running:
            return
        try:
            record = adapter.to_record(packet)
            if record is not None:
                if len(learning_records) < 10000:
                    learning_records.append(record)
                if 0 < len(learning_records) < 10000 and len(learning_records) % 50 == 0:
                    dash.update_stats({
                        "packets": len(learning_records),
                        "training_status": (
                            f"learning: {len(learning_records)} samples "
                            f"/ {min_training_samples} minimum"
                        ),
                        "monitoring": False,
                    })
        except Exception as exc:
            dash.log_system(f"Learning packet skipped: {type(exc).__name__}: {exc}", "yellow")

    try:
        sniff(
            iface=interface,
            filter=bpf_filter,
            prn=collect_packet,
            store=False,
            timeout=learn_seconds,
        )
    except PermissionError as exc:
        raise SystemExit(
            "Packet capture permission denied. Run with appropriate local "
            "capture privileges or configure Npcap on Windows."
        ) from exc

    if not _running:
        return
    if len(learning_records) < min_training_samples:
        dash.log_system(
            f"Learning stopped: captured {len(learning_records)} records; "
            f"{min_training_samples} required. No live detector enabled.",
            "red",
        )
        raise SystemExit(
            f"Insufficient learning traffic ({len(learning_records)} records). "
            f"Retry with a longer --learn-seconds value; no synthetic fallback was used."
        )

    try:
        calibration = detector.fit_live_baseline(
            learning_records, min_samples=min_training_samples
        )
    except (ValueError, FloatingPointError) as exc:
        raise SystemExit(f"Could not calibrate live baseline: {exc}") from exc

    # Persist feature-only baseline for repeatable local benchmarking.
    # Private IP addresses and packet payload bytes are deliberately excluded.
    baseline_path = Path("logs/live_baseline.jsonl")
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    with baseline_path.open("w", encoding="utf-8") as baseline_file:
        for row in learning_records:
            safe_row = {
                key: value for key, value in row.items()
                if key not in {"src_ip", "dst_ip"}
            }
            baseline_file.write(json.dumps(safe_row) + "\n")

    # Do not retain the learning records after fitting.
    sample_count = len(learning_records)
    learning_records.clear()
    dash.log_system(
        f"Baseline ready: {calibration['training_samples']} fit samples, "
        f"{calibration['calibration_samples']} held-out calibration samples.",
        "green",
    )
    dash.log_system(
        "Calibration tail is not an independent FPR measurement; "
        "learning-window traffic is not verified attack-free.",
        "yellow",
    )
    dash.update_stats({
        "packets": 0,
        "alerts": 0,
        "training_status": detector.training_status,
        "monitoring": True,
        "mode": "PASSIVE LIVE",
        "phase": "monitoring",
    })

    def on_packet(packet):
        if not _running:
            return
        try:
            record = adapter.to_record(packet)
            if record is not None:
                _handle_record(record)
        except Exception as exc:
            dash.log_system(f"Packet skipped: {type(exc).__name__}: {exc}", "yellow")

    dash.log_system(
        f"Live monitoring enabled after {sample_count} learning records; "
        "candidate alerts only.",
        "cyan",
    )
    try:
        sniff(
            iface=interface,
            filter=bpf_filter,
            prn=on_packet,
            store=False,
            stop_filter=lambda _packet: not _running,
        )
    except PermissionError as exc:
        raise SystemExit(
            "Packet capture permission denied. Check Npcap and capture privileges."
        ) from exc


def _build_alert(aid, pkt, result, analysis):
    return {
        "id": aid,
        "timestamp": time.strftime("%H:%M:%S"),
        "src_ip": pkt.get("src_ip", "?"),
        "dst_ip": pkt.get("dst_ip", "?"),
        "protocol": pkt.get("protocol", "UNKNOWN"),
        "dst_port": pkt.get("dst_port", 0),
        "severity": result["severity"],
        "score": result["anomaly_score"],
        "decision_threshold": result.get("decision_threshold"),
        "baseline_mode": result.get("baseline_mode"),
        "threat_type": result["threat_type"],
        "analysis": analysis,
        "proposed_response": result["proposed_response"],
    }


def _print_summary():
    alerts = log.all()
    sev = log.severity_counts()
    stats = detector.stats
    print("\n" + "═" * 60)
    print("  AI-IDS SESSION SUMMARY")
    print("═" * 60)
    print(f"  Records analysed : {stats['total_analyzed']:,}")
    print(f"  Anomalies found  : {stats['total_anomalies']:,}")
    print(
        f"  Anomaly ratio    : "
        f"{stats['total_anomalies'] / max(stats['total_analyzed'], 1) * 100:.1f}% "
        "(not accuracy)"
    )
    print(f"  Model status     : {detector.training_status}")
    print(f"  Alerts logged    : {len(alerts)}")
    print("\n  SEVERITY BREAKDOWN")
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        print(f"    {level:<9} {'█' * sev.get(level, 0)} {sev.get(level, 0)}")
    print("\n  Alert log saved  : logs/alerts.json")
    if alerts:
        generate_report(alerts, detector, "logs/session_report.txt")
        print("  Full report      : logs/session_report.txt")
    print("═" * 60)


def main():
    global dash, _running
    parser = argparse.ArgumentParser(
        description="AI-IDS: simulation, benchmark evaluation, and passive capture"
    )
    parser.add_argument(
        "--mode", choices=("simulator", "live"), default="simulator",
        help="Traffic source: synthetic simulator (default) or passive live capture",
    )
    parser.add_argument("--attack", choices=list(ATTACK_PROFILES), metavar="TYPE")
    parser.add_argument("--demo", action="store_true",
                        help="Run scripted simulator attack waves")
    parser.add_argument(
        "--demo-duration", type=int, default=32,
        help="Duration of the scripted demo in seconds (default: 32)",
    )
    parser.add_argument(
        "--demo-count", type=int, default=12,
        help="Synthetic records per scripted attack scenario (default: 12)",
    )
    parser.add_argument("--speed", type=int, default=5, metavar="N",
                        help="Simulator records per second (default: 5)")
    parser.add_argument("--interface", help="Capture interface name for --mode live")
    parser.add_argument("--bpf-filter", help="Optional Scapy/BPF capture filter")
    parser.add_argument(
        "--learn-seconds", type=int, default=30,
        help="Live-mode quiet baseline collection window in seconds (default: 30)",
    )
    parser.add_argument(
        "--min-training-samples", type=int, default=200,
        help="Minimum captured records required before live monitoring (default: 200)",
    )

    args = parser.parse_args()
    if args.speed < 1:
        parser.error("--speed must be at least 1")
    if args.demo_duration < 26:
        parser.error("--demo-duration must be at least 26 seconds to show all four scenarios")
    if args.demo_count < 1:
        parser.error("--demo-count must be at least 1")
    if args.learn_seconds < 1:
        parser.error("--learn-seconds must be at least 1")
    if args.min_training_samples < 100:
        parser.error("--min-training-samples must be at least 100")
    if args.mode == "live" and (args.demo or args.attack):
        parser.error("--demo and --attack are simulator-only; use --mode simulator")

    dash = Dashboard()
    dash.update_stats({
        "mode": "SIMULATOR DEMO" if args.mode == "simulator" else "PASSIVE LIVE",
        "phase": "standby",
    })
    dash.log_system(f"LLM backend: {llm.backend}", "cyan")
    dash.log_system(f"Mode: {'PASSIVE LIVE CAPTURE' if args.mode == 'live' else 'SIMULATOR'}", "cyan")

    if args.mode == "simulator":
        dash.log_system(
            "Simulator uses synthetic baseline and labels; not live-network validation.",
            "yellow",
        )
    else:
        dash.log_system(
            "Live mode starts with a fresh baseline; synthetic fallback is disabled.",
            "yellow",
        )

    if args.mode == "simulator" and args.demo:
        dash.log_system(
            f"Video demo: 4 scripted scenarios | {args.demo_count} records each | {args.demo_duration}s",
            "cyan",
        )
        demo_mode(duration=args.demo_duration, count=args.demo_count)
    elif args.mode == "simulator" and args.attack:
        threading.Thread(
            target=inject_attack, args=(args.attack, 20, 3.0), daemon=True
        ).start()

    try:
        if args.mode == "live":
            live_capture_loop(
                args.interface, args.bpf_filter,
                learn_seconds=args.learn_seconds,
                min_training_samples=args.min_training_samples,
            )
        else:
            simulator_loop(packets_per_second=args.speed)
    except KeyboardInterrupt:
        pass
    finally:
        _running = False
        dash.close()
        _print_summary()


if __name__ == "__main__":
    main()
