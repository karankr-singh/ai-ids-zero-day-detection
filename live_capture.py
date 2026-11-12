"""Passive Scapy packet capture adapter for the AI-IDS prototype.

Only packet metadata and payload entropy are extracted. Payload bytes are never
stored, printed, or sent to the LLM. This is a prototype sensor, not a
production-grade flow engine.
"""
from collections import defaultdict
import math
import time


def _entropy(payload: bytes) -> float:
    if not payload:
        return 0.0
    counts = [0] * 256
    for value in payload:
        counts[value] += 1
    length = len(payload)
    return -sum((count / length) * math.log2(count / length)
                for count in counts if count)


class ScapyCapture:
    """Convert observed IPv4 TCP/UDP packets into detector-compatible records."""

    def __init__(self):
        self._last_seen = {}
        self._flow_started = {}
        self._flow_bytes = defaultdict(int)

    def to_record(self, packet):
        from scapy.layers.inet import IP, TCP, UDP

        if IP not in packet:
            return None
        ip = packet[IP]
        if TCP in packet:
            transport = packet[TCP]
            protocol = "TCP"
            src_port, dst_port = int(transport.sport), int(transport.dport)
            flags = int(transport.flags)
        elif UDP in packet:
            transport = packet[UDP]
            protocol = "UDP"
            src_port, dst_port = int(transport.sport), int(transport.dport)
            flags = 0
        else:
            protocol = str(ip.proto)
            src_port = dst_port = flags = 0

        now = float(getattr(packet, "time", time.time()))
        key = (ip.src, ip.dst, protocol, src_port, dst_port)
        previous = self._last_seen.get(key, now)
        started = self._flow_started.setdefault(key, now)
        size = int(len(packet))
        self._last_seen[key] = now
        self._flow_bytes[key] += size
        payload = bytes(transport.payload) if TCP in packet or UDP in packet else b""

        return {
            "src_ip": str(ip.src), "dst_ip": str(ip.dst),
            "src_port": src_port, "dst_port": dst_port,
            "protocol": protocol, "packet_size": size,
            "inter_arrival_ms": max(0.0, (now - previous) * 1000.0),
            "flags": flags, "ttl": int(ip.ttl),
            "payload_entropy": _entropy(payload),
            "flow_duration_ms": max(0.0, (now - started) * 1000.0),
            "bytes_per_second": self._flow_bytes[key] / max(now - started, 0.001),
            "timestamp": now, "source": "live_capture",
        }
