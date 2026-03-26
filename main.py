import argparse
import signal
import sys
import time
import threading

from detector  import AnomalyDetector
from simulator import AttackSimulator, ATTACK_PROFILES
from llm_engine import LLMEngine
from logger    import AlertLogger
from dashboard import Dashboard
from report    import generate_report


# ── Globals ───────────────────────────────────────────────────────
_running = True
_alert_id = 0

detector  = AnomalyDetector()
simulator = AttackSimulator()
llm       = LLMEngine()
log       = AlertLogger("logs/alerts.json")
dash      = None          # initialised after arg parsing


# ── Signal handler (Ctrl+C) ───────────────────────────────────────
def _on_exit(sig, frame):
    global _running
    _running = False

signal.signal(signal.SIGINT, _on_exit)


# ── Core monitoring loop ──────────────────────────────────────────
def monitoring_loop(packets_per_second: int = 5):
    """
    Continuously generate packets, analyse them, and push results
    to the dashboard.  Runs in the main thread.
    """
    global _alert_id
    interval = 1.0 / packets_per_second

    while _running:
        pkt = simulator.generate_packet()
        result = detector.analyze(pkt)

        dash.add_normal_tick()
        dash.update_stats({
            "packets":    detector.stats["total_analyzed"],
            "alerts":     len(log),
            "accuracy":   detector.accuracy,
            "fpr":        detector.fpr,
            "monitoring": True,
        })

        if result["is_anomaly"]:
            _alert_id += 1
            analysis = llm.analyze(pkt, result)
            alert = _build_alert(_alert_id, pkt, result, analysis)
            log.add(alert)
            dash.add_alert(alert)

            # Detailed console log for CRITICAL / HIGH
            if result["severity"] in ("CRITICAL", "HIGH"):
                dash.log_system(
                    f"{result['severity']} | {result['threat_type']} | "
                    f"{pkt['src_ip']} → {pkt['dst_ip']} | {result['response_action']}",
                    "red" if result["severity"] == "CRITICAL" else "yellow",
                )

        time.sleep(interval)


# ── Attack injection ──────────────────────────────────────────────
def inject_attack(attack_key: str, count: int = 15, delay: float = 2.0):
    """Inject a burst of attack packets after a short delay."""
    global _alert_id
    time.sleep(delay)
    if not _running:
        return
    dash.log_system(f"Injecting attack: {attack_key.upper()} ({count} packets)", "yellow")

    packets = simulator.inject_attack(attack_key, count)
    for pkt in packets:
        result = detector.analyze(pkt)
        dash.add_normal_tick()
        if result["is_anomaly"]:
            _alert_id += 1
            analysis = llm.analyze(pkt, result)
            alert = _build_alert(_alert_id, pkt, result, analysis)
            log.add(alert)
            dash.add_alert(alert)
        time.sleep(0.05)

    dash.log_system(
        f"Attack injection complete — {sum(1 for a in log.recent(count) if a)} alerts generated",
        "green",
    )
    dash.update_stats({
        "packets":  detector.stats["total_analyzed"],
        "alerts":   len(log),
        "accuracy": detector.accuracy,
        "fpr":      detector.fpr,
    })


# ── Demo mode ─────────────────────────────────────────────────────
def demo_mode(duration: int = 45):
    """
    Run a scripted 45-second demo: normal traffic + 3 attack waves.
    """
    attacks = [
        (8,  "port_scan"),
        (18, "ddos"),
        (30, "data_exfiltration"),
        (38, "brute_force"),
    ]
    for delay, key in attacks:
        t = threading.Thread(target=inject_attack, args=(key, 12, delay), daemon=True)
        t.start()

    # retrain midway
    def _retrain():
        time.sleep(22)
        if _running:
            dash.log_system("Auto-retraining model on accumulated data...", "cyan")
            ok = detector.retrain()
            if ok:
                dash.log_system(
                    f"Retraining complete — accuracy: {detector.accuracy*100:.1f}%", "green"
                )
    threading.Thread(target=_retrain, daemon=True).start()

    # End demo after `duration` seconds
    def _stopper():
        time.sleep(duration)
        global _running
        _running = False
    threading.Thread(target=_stopper, daemon=True).start()


# ── Helper ────────────────────────────────────────────────────────
def _build_alert(aid: int, pkt: dict, result: dict, analysis: str) -> dict:
    return {
        "id":          aid,
        "timestamp":   time.strftime("%H:%M:%S"),
        "src_ip":      pkt["src_ip"],
        "dst_ip":      pkt["dst_ip"],
        "protocol":    pkt["protocol"],
        "dst_port":    pkt["dst_port"],
        "severity":    result["severity"],
        "score":       result["anomaly_score"],
        "threat_type": result["threat_type"],
        "analysis":    analysis,
        "action":      result["response_action"],
        "confidence":  result["confidence"],
    }


# ── Entry point ───────────────────────────────────────────────────
def main():
    global dash

    parser = argparse.ArgumentParser(
        description="AI-IDS: AI-Driven Intrusion Detection System"
    )
    parser.add_argument(
        "--attack", metavar="TYPE",
        choices=list(ATTACK_PROFILES.keys()),
        help=f"Inject a specific attack. Choices: {list(ATTACK_PROFILES.keys())}",
    )
    parser.add_argument(
        "--demo", action="store_true",
        help="Run a scripted 45-second demo with multiple attack waves",
    )
    parser.add_argument(
        "--speed", type=int, default=5, metavar="N",
        help="Packets per second to analyse (default: 5)",
    )
    args = parser.parse_args()

    # ── Start dashboard ──────────────────────────────────────────
    dash = Dashboard()
    dash.log_system(f"LLM backend: {llm.backend}", "cyan")
    dash.log_system(
        f"Mode: {'DEMO' if args.demo else ('ATTACK=' + args.attack) if args.attack else 'LIVE MONITORING'}",
        "cyan",
    )

    if args.demo:
        demo_mode()
    elif args.attack:
        t = threading.Thread(target=inject_attack, args=(args.attack, 20, 3.0), daemon=True)
        t.start()

    # ── Main loop ────────────────────────────────────────────────
    try:
        monitoring_loop(packets_per_second=args.speed)
    finally:
        dash.close()
        _print_summary()


def _print_summary():
    """Print a final session summary after the dashboard closes."""
    alerts = log.all()
    sev    = log.severity_counts()
    stats  = detector.stats

    print("\n" + "═" * 60)
    print("  AI-IDS SESSION SUMMARY")
    print("═" * 60)
    print(f"  Packets analysed : {stats['total_analyzed']:,}")
    print(f"  Anomalies found  : {stats['total_anomalies']:,}")
    print(f"  Detection rate   : {stats['total_anomalies'] / max(stats['total_analyzed'],1)*100:.1f}%")
    print(f"  Model accuracy   : {detector.accuracy*100:.1f}%")
    print(f"  False positive   : {detector.fpr*100:.1f}%")
    print(f"  Alerts logged    : {len(alerts)}")
    print()
    print("  SEVERITY BREAKDOWN")
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        bar = "█" * sev.get(level, 0)
        print(f"    {level:<9} {bar} {sev.get(level, 0)}")
    print()
    print(f"  Alert log saved  : logs/alerts.json")
    print("═" * 60)

    if alerts:
        generate_report(alerts, detector, "logs/session_report.txt")
        print("  Full report      : logs/session_report.txt")
        print("═" * 60)

    print()


if __name__ == "__main__":
    main()
