try:
    import urllib.request as _ur
    import json as _json
    _HTTP_AVAILABLE = True
except ImportError:
    _HTTP_AVAILABLE = False

OLLAMA_URL   = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "tinyllama"


class LLMEngine:
    def __init__(self):
        self._ollama_ok = self._probe_ollama()

    # ── Public API ────────────────────────────────────────────────
    def analyze(self, pkt: dict, result: dict) -> str:
        """Return a human-readable threat analysis string."""
        if self._ollama_ok:
            reply = self._call_ollama(pkt, result)
            if reply:
                return reply
        return self._expert_analysis(pkt, result)

    @property
    def backend(self) -> str:
        return "Ollama / Llama 3" if self._ollama_ok else "Expert Rule Engine"

    # ── Ollama integration ────────────────────────────────────────
    def _probe_ollama(self) -> bool:
        if not _HTTP_AVAILABLE:
            return False
        try:
            req = _ur.Request("http://localhost:11434/api/tags")
            with _ur.urlopen(req, timeout=2) as r:
                return r.status == 200
        except Exception:
            return False

    def _call_ollama(self, pkt: dict, result: dict) -> str:
        prompt = (
            "You are a cybersecurity analyst AI. Analyze this network anomaly "
            "briefly (3–4 sentences max).\n\n"
            f"Packet: src={pkt.get('src_ip')} dst={pkt.get('dst_ip')}:{pkt.get('dst_port')} "
            f"proto={pkt.get('protocol')} size={pkt.get('packet_size')}B "
            f"entropy={pkt.get('payload_entropy')} inter={pkt.get('inter_arrival_ms')}ms "
            f"ttl={pkt.get('ttl')} flags={pkt.get('flags')}\n"
            f"Detection: {result.get('threat_type')} | "
            f"Severity: {result.get('severity')} | "
            f"Score: {result.get('anomaly_score')}\n\n"
            "Provide: threat assessment, likely attack vector, recommended action. Be concise."
        )
        payload = _json.dumps({
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.3, "num_predict": 120},
        }).encode()
        try:
            req = _ur.Request(OLLAMA_URL, data=payload,
                              headers={"Content-Type": "application/json"})
            with _ur.urlopen(req, timeout=10) as r:
                data = _json.loads(r.read())
                return data.get("response", "").strip()
        except Exception:
            return ""

    # ── Expert rule engine (fallback) ─────────────────────────────
    def _expert_analysis(self, pkt: dict, result: dict) -> str:
        threat  = result.get("threat_type", "Unknown Anomaly")
        sev     = result.get("severity", "LOW")
        score   = result.get("anomaly_score", 0)
        src     = pkt.get("src_ip", "?")
        port    = pkt.get("dst_port", 0)
        size    = pkt.get("packet_size", 0)
        entropy = pkt.get("payload_entropy", 4.0)
        inter   = pkt.get("inter_arrival_ms", 20)
        pps     = round(1000 / max(inter, 0.1))

        templates = {
            "Port Scan": (
                f"Source {src} is enumerating ports at ~{pps} pkt/s with minimal payload "
                f"({size}B), a pattern consistent with automated tools (nmap/masscan). "
                f"Target is mapping open services for later exploitation. "
                f"Recommend: block {src} at perimeter and audit exposed services."
            ),
            "DDoS Flood": (
                f"Volumetric flood from {src} — estimated {pps} pkt/s. "
                f"Low-entropy uniform packets (entropy={entropy:.2f}) suggest botnet origin. "
                f"Recommend: activate rate-limiting, engage upstream scrubbing, block source CIDR."
            ),
            "Data Exfiltration": (
                f"Outbound transfer to {src} on non-standard port {port}. "
                f"High payload entropy ({entropy:.2f}/8.0) and large size ({size}B) "
                f"indicate encrypted/compressed staged exfil. "
                f"Recommend: block connection immediately, preserve forensic logs, begin IR."
            ),
            "Brute Force Attack": (
                f"Auth-spray from {src} targeting port {port} at {pps} attempts/s. "
                f"Exceeds normal login rates — credential stuffing or dictionary attack. "
                f"Recommend: enforce account lockout, block {src}, enable MFA."
            ),
            "Encrypted C2 Channel": (
                f"Regular beaconing ({inter:.0f}ms interval) with high entropy ({entropy:.2f}) "
                f"from internal host to {src}. Consistent with post-exploitation RAT. "
                f"Recommend: isolate host, forensic analysis, hunt for lateral movement."
            ),
            "NULL / Malformed Packet": (
                f"NULL-flag TCP packets from {src} — a known firewall-evasion technique. "
                f"Anomaly score {score:.3f} indicates deliberate crafting. "
                f"Recommend: drop packets, harden firewall ruleset, monitor {src}."
            ),
        }

        analysis = templates.get(threat, (
            f"Unclassified anomaly from {src} — score {score:.3f} deviates from baseline. "
            f"Packet profile (size={size}B, entropy={entropy:.2f}, port={port}) "
            f"does not match any known signature — potential zero-day vector. "
            f"Recommend: manual investigation and increased monitoring."
        ))

        if sev == "CRITICAL":
            analysis += " ⚠️  AUTOMATED RESPONSE INITIATED."
        return analysis
