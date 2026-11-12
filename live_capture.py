"""Passive Scapy packet capture adapter for the AI-IDS prototype.

Only packet metadata and payload entropy are extracted. Payload bytes are never
stored, printed, or sent to the LLM. Per-flow state is bounded to avoid
unbounded memory growth during long capture sessions.
"""
from collections import OrderedDict
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

    def __init__(self, max_flows: int = 10000):
        self.max_flows = max_flows
        self._flows = OrderedDict()

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
        flow = self._flows.get(key)
        if flow is None:
            flow = {"last_seen": now, "started": now, "bytes": 0}
            self._flows[key] = flow
        else:
            self._flows.move_to_end(key)

        size = int(len(packet))
        inter_arrival_ms = max(0.0, (now - flow["last_seen"]) * 1000.0)
        flow["last_seen"] = now
        flow["bytes"] += size
        if len(self._flows) > self.max_flows:
            self._flows.popitem(last=False)

        # Payload bytes exist only in this local calculation and are not retained.
        payload = bytes(transport.payload) if TCP in packet or UDP in packet else b""
        duration = max(0.0, now - flow["started"])
        return {
            "src_ip": str(ip.src), "dst_ip": str(ip.dst),
            "src_port": src_port, "dst_port": dst_port,
            "protocol": protocol, "packet_size": size,
            "inter_arrival_ms": inter_arrival_ms,
            "flags": flags, "ttl": int(ip.ttl),
            "payload_entropy": _entropy(payload),
            "flow_duration_ms": duration * 1000.0,
            "bytes_per_second": flow["bytes"] / max(duration, 0.001),
            "timestamp": now, "source": "live_capture",
        }
