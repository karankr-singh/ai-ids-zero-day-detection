import time
from collections import Counter
from pathlib import Path


def generate_report(alerts: list, detector, filepath: str):
    """Write a structured session report to `filepath`."""
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)

    sev    = Counter(a.get("severity",    "LOW")     for a in alerts)
    threat = Counter(a.get("threat_type", "Unknown") for a in alerts)
    proto  = Counter(a.get("protocol",    "TCP")     for a in alerts)
    stats  = detector.stats

    lines = [
        "=" * 64,
        "  AI-IDS SESSION REPORT",
        f"  Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 64,
        "",
        "── DETECTION STATISTICS ─────────────────────────────────",
        f"  Packets analysed  : {stats['total_analyzed']:,}",
        f"  Anomalies detected: {stats['total_anomalies']:,}",
        f"  Detection rate    : {stats['total_anomalies'] / max(stats['total_analyzed'],1)*100:.1f}%",
        f"  Model accuracy    : {detector.accuracy*100:.1f}%",
        f"  False positive    : {detector.fpr*100:.1f}%",
        "",
        "── SEVERITY DISTRIBUTION ────────────────────────────────",
    ]
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        bar = "█" * sev.get(level, 0)
        lines.append(f"  {level:<9} {bar or '(none)'} ({sev.get(level, 0)})")

    lines += [
        "",
        "── THREAT TYPES DETECTED ────────────────────────────────",
    ]
    for threat_type, count in threat.most_common():
        lines.append(f"  {count:>4}×  {threat_type}")

    lines += [
        "",
        "── PROTOCOL BREAKDOWN ───────────────────────────────────",
    ]
    for p, count in proto.most_common():
        lines.append(f"  {count:>4}×  {p}")

    lines += [
        "",
        "── TOP ALERT DETAILS (most recent 10) ───────────────────",
    ]
    for a in alerts[-10:]:
        lines.append(
            f"  [{a.get('timestamp','')}] {a.get('severity','?'):8} "
            f"{a.get('threat_type','?')}"
        )
        lines.append(
            f"            SRC={a.get('src_ip','?')}  DST={a.get('dst_ip','?')}"
            f":{a.get('protocol','?')}"
        )
        lines.append(f"            SCORE={a.get('score',0):.4f}  CONF={a.get('confidence',0):.3f}")
        lines.append(f"            ACTION: {a.get('action','?')}")
        if a.get("analysis"):
            # Wrap at 60 chars
            words = a["analysis"].split()
            line_buf, wrapped = [], []
            for w in words:
                if sum(len(x)+1 for x in line_buf) + len(w) > 58:
                    wrapped.append("            " + " ".join(line_buf))
                    line_buf = [w]
                else:
                    line_buf.append(w)
            if line_buf:
                wrapped.append("            " + " ".join(line_buf))
            lines.append("            Analysis:")
            lines.extend(wrapped)
        lines.append("")

    lines.append("=" * 64)

    path.write_text("\n".join(lines))
