import random
import time


# ── Normal service profiles ──────────────────────────────────────
NORMAL_SERVICES = [
    {"port": 80,    "proto": "HTTP",   "size_mean": 512, "size_std": 180},
    {"port": 443,   "proto": "HTTPS",  "size_mean": 600, "size_std": 200},
    {"port": 22,    "proto": "SSH",    "size_mean": 256, "size_std":  80},
    {"port": 53,    "proto": "DNS",    "size_mean":  80, "size_std":  30},
    {"port": 3306,  "proto": "MySQL",  "size_mean": 400, "size_std": 150},
    {"port": 8080,  "proto": "HTTP",   "size_mean": 450, "size_std": 160},
    {"port": 25,    "proto": "SMTP",   "size_mean": 350, "size_std": 120},
    {"port": 21,    "proto": "FTP",    "size_mean": 200, "size_std":  80},
]

# ── Attack profiles ───────────────────────────────────────────────
ATTACK_PROFILES = {
    "port_scan": {
        "label":       "Port Scan",
        "description": "Sequential port enumeration to map open services",
        "size_range":  (40,   80),
        "inter_range": (0.5,  3.0),
        "flags":       2,          # SYN only
        "port_range":  (1,    1024),
        "entropy":     (1.0,  2.5),
        "ttl_range":   (45,   55),
    },
    "ddos": {
        "label":       "DDoS Flood",
        "description": "High-volume packet flood targeting a single host",
        "size_range":  (60,   120),
        "inter_range": (0.1,  1.5),
        "flags":       2,
        "port_range":  (80,   80),
        "entropy":     (0.5,  1.5),
        "ttl_range":   (30,   50),
    },
    "data_exfiltration": {
        "label":       "Data Exfiltration",
        "description": "Large encrypted payload exfiltration over unusual port",
        "size_range":  (1200, 1500),
        "inter_range": (5.0,  15.0),
        "flags":       24,         # PSH + ACK
        "port_range":  (4444, 9999),
        "entropy":     (7.2,  7.95),
        "ttl_range":   (60,   70),
    },
    "brute_force": {
        "label":       "Brute Force",
        "description": "Rapid repeated authentication attempts on SSH/RDP",
        "size_range":  (100,  200),
        "inter_range": (1.0,  5.0),
        "flags":       24,
        "port_range":  (22,   22),
        "entropy":     (3.5,  5.0),
        "ttl_range":   (55,   65),
    },
    "c2_beacon": {
        "label":       "C2 Beacon",
        "description": "Periodic encrypted command-and-control channel beaconing",
        "size_range":  (800,  1200),
        "inter_range": (8.0,  12.0),
        "flags":       24,
        "port_range":  (443,  8443),
        "entropy":     (7.5,  7.95),
        "ttl_range":   (60,   70),
    },
    "null_scan": {
        "label":       "NULL Scan",
        "description": "Zero-flag TCP packets to evade stateful firewalls",
        "size_range":  (40,   60),
        "inter_range": (2.0,  8.0),
        "flags":       0,          # NULL flags
        "port_range":  (1,    65535),
        "entropy":     (0.0,  1.0),
        "ttl_range":   (40,   55),
    },
}


def _port_to_proto(port: int) -> str:
    return {80: "HTTP", 443: "HTTPS", 22: "SSH", 53: "DNS",
            3389: "RDP", 21: "FTP", 23: "Telnet", 25: "SMTP",
            3306: "MySQL", 8080: "HTTP", 8443: "HTTPS"}.get(port, "TCP")


class AttackSimulator:
    """
    Generates synthetic network packets.

    Usage:
        sim = AttackSimulator()
        pkt  = sim.generate_packet()          # one normal-or-random packet
        pkts = sim.inject_attack("ddos", 20)  # 20 DDoS packets
    """

    def __init__(self):
        # Realistic IP pools
        self._external_ips = [
            f"{random.randint(1,223)}.{random.randint(0,255)}."
            f"{random.randint(0,255)}.{random.randint(1,254)}"
            for _ in range(60)
        ]
        self._internal_ips = [f"192.168.1.{i}" for i in range(2, 25)]

    # ── Public API ───────────────────────────────────────────────
    def generate_packet(self) -> dict:
        """
        Return a single packet — ~8 % chance of being an anomalous
        attack packet, otherwise normal traffic.
        """
        if random.random() < 0.08:
            return self._make_attack_pkt(random.choice(list(ATTACK_PROFILES)))
        return self._make_normal_pkt()

    def inject_attack(self, attack_key: str, count: int = 10) -> list[dict]:
        """Return `count` packets of the specified attack type."""
        if attack_key not in ATTACK_PROFILES:
            raise ValueError(f"Unknown attack type: {attack_key}. "
                             f"Choose from: {list(ATTACK_PROFILES)}")
        return [self._make_attack_pkt(attack_key) for _ in range(count)]

    @staticmethod
    def list_attacks() -> dict:
        return {k: v["description"] for k, v in ATTACK_PROFILES.items()}

    # ── Internal builders ────────────────────────────────────────
    def _make_normal_pkt(self) -> dict:
        svc = random.choice(NORMAL_SERVICES)
        size = max(40, int(random.gauss(svc["size_mean"], svc["size_std"])))
        inter = max(0.5, random.gauss(20, 8))
        return {
            "src_ip":           random.choice(self._internal_ips),
            "dst_ip":           random.choice(self._external_ips),
            "src_port":         random.randint(1024, 65535),
            "dst_port":         svc["port"],
            "protocol":         svc["proto"],
            "packet_size":      size,
            "inter_arrival_ms": inter,
            "flags":            random.choice([2, 18, 16, 24]),
            "ttl":              random.randint(55, 70),
            "payload_entropy":  round(max(0, random.gauss(4.2, 0.6)), 4),
            "flow_duration_ms": max(10, random.gauss(300, 100)),
            "bytes_per_second": max(100, size / max(inter / 1000, 0.001)),
            "timestamp":        time.time(),
            "pkt_type":         "normal",
        }

    def _make_attack_pkt(self, key: str) -> dict:
        p = ATTACK_PROFILES[key]
        size  = random.randint(*p["size_range"])
        inter = random.uniform(*p["inter_range"])
        port  = random.randint(*p["port_range"])
        return {
            "src_ip":           random.choice(self._external_ips),
            "dst_ip":           random.choice(self._internal_ips),
            "src_port":         random.randint(1024, 65535),
            "dst_port":         port,
            "protocol":         _port_to_proto(port),
            "packet_size":      size,
            "inter_arrival_ms": inter,
            "flags":            p["flags"],
            "ttl":              random.randint(*p["ttl_range"]),
            "payload_entropy":  round(random.uniform(*p["entropy"]), 4),
            "flow_duration_ms": inter * random.randint(5, 20),
            "bytes_per_second": size / max(inter / 1000, 0.001),
            "timestamp":        time.time(),
            "pkt_type":         key,
        }
