import argparse
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
    if result["is_anomaly"]:
        _alert_id += 1
        analysis = llm.analyze(pkt, result)
        alert = _build_alert(_alert_id, pkt, result, analysis)
        log.add(alert)
        dash.add_alert(alert)
        if result["severity"] in ("CRITICAL", "HIGH"):
            dash.log_system(
                f"{result['severity']} | {result['threat_type']} | "
                f"{pkt['src_ip']} → {pkt['dst_ip']} | {result['proposed_response']}",
                "red" if result["severity"] == "CRITICAL" else "yellow",
            )
    else:
        dash.add_normal_tick()

    stats = detector.stats
    dash.update_stats({
        "packets": stats["total_analyzed"],
        "alerts": len(log),
        "training_status": detector.training_status,
        "monitoring": True,
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
    global _alert_id
    time.sleep(delay)
    if not _running:
        return
    dash.log_system(
        f"Injecting simulated attack: {attack_key.upper()} ({count} records)",
        "yellow",
    )
    for pkt in simulator.inject_attack(attack_key, count):
        _handle_record(pkt)
        time.sleep(0.05)
    dash.log_system("Simulated attack injection complete", "green")


def demo_mode(duration=45):
    attacks = [(8, "port_scan"), (18, "ddos"),
               (30, "data_exfiltration"), (38, "brute_force")]
    for delay, key in attacks:
        threading.Thread(
            target=inject_attack, args=(key, 12, delay), daemon=True
        ).start()

    def stop_demo():
        global _running
        time.sleep(duration)
        _running = False

    threading.Thread(target=stop_demo, daemon=True).start()


def live_capture_loop(interface=None, bpf_filter=None):
    """Passively observe packets; never inject, modify, or block traffic."""
    try:
        from scapy.all import sniff
    except ImportError as exc:
        raise SystemExit(
            "Scapy is required for live capture. Install it with: pip install scapy"
        ) from exc

    from live_capture import ScapyCapture

    adapter = ScapyCapture()
    dash.log_system("Passive capture enabled; payload contents are not stored", "cyan")
    dash.log_system(
        f"Interface: {interface or 'Scapy default'} | BPF: {bpf_filter or 'none'}",
        "cyan",
    )

    def on_packet(packet):
        if not _running:
            return
        try:
            record = adapter.to_record(packet)
            if record is not None:
                _handle_record(record)
        except Exception as exc:
            dash.log_system(f"Packet skipped: {type(exc).__name__}: {exc}", "yellow")

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
            "Packet capture permission denied. Run with appropriate local "
            "capture privileges or configure Npcap on Windows."
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
    parser.add_argument("--speed", type=int, default=5, metavar="N",
                        help="Simulator records per second (default: 5)")
    parser.add_argument("--interface", help="Capture interface name for --mode live")
    parser.add_argument("--bpf-filter", help="Optional Scapy/BPF capture filter")

    args = parser.parse_args()
    if args.speed < 1:
        parser.error("--speed must be at least 1")
    if args.mode == "live" and (args.demo or args.attack):
        parser.error("--demo and --attack are simulator-only; use --mode simulator")

    dash = Dashboard()
    dash.log_system(f"LLM backend: {llm.backend}", "cyan")
    dash.log_system(f"Mode: {'PASSIVE LIVE CAPTURE' if args.mode == 'live' else 'SIMULATOR'}", "cyan")
    dash.log_system(
        "Warning: live mode uses the prototype synthetic baseline; detections "
        "are exploratory, not calibrated or benchmark-validated.",
        "yellow",
    )

    if args.mode == "simulator" and args.demo:
        demo_mode()
    elif args.mode == "simulator" and args.attack:
        threading.Thread(
            target=inject_attack, args=(args.attack, 20, 3.0), daemon=True
        ).start()

    try:
        if args.mode == "live":
            live_capture_loop(args.interface, args.bpf_filter)
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
