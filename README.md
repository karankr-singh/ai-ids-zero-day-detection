# AI-IDS — AI-Driven Intrusion Detection System
### Local Python Script Version  |  Final Year Project

---

## ⚡ Quick Start (2 steps)

```bash
pip install -r requirements.txt
python main.py
```

That's it. A full-screen live dashboard opens in your terminal.

---

## 🚀 Run Modes

| Command | What it does |
|---|---|
| `python main.py` | Live monitoring (Ctrl+C to stop) |
| `python main.py --demo` | 45-sec scripted demo with 4 attack waves |
| `python main.py --attack port_scan` | Inject a port scan attack |
| `python main.py --attack ddos` | Inject a DDoS attack |
| `python main.py --attack data_exfiltration` | Inject data exfil attack |
| `python main.py --attack brute_force` | Inject brute force attack |
| `python main.py --attack c2_beacon` | Inject C2 beacon attack |
| `python main.py --attack null_scan` | Inject NULL scan attack |
| `python main.py --speed 10` | Analyse 10 packets/second |

---

## 📁 File Structure

```
ai_ids_local/
│
├── main.py          # ← ENTRY POINT — run this
├── detector.py      # Isolation Forest ML engine
├── simulator.py     # Network traffic & attack generator
├── llm_engine.py    # LLM reasoning (Ollama/expert fallback)
├── logger.py        # Alert storage + file persistence
├── dashboard.py     # Live Rich terminal dashboard
├── report.py        # Post-session report generator
├── requirements.txt # pip install -r requirements.txt
└── logs/
    ├── alerts.json         # All alerts (JSONL)
    └── session_report.txt  # Summary report after exit
```

---

## 🖥️ Dashboard Layout

```
┌─ Header: Packets | Alerts | Accuracy | FPR | Status ─────────┐
├─ Live Alert Feed ─────────────┬─ Traffic Sparklines ──────────┤
│  ● CRITICAL  Port Scan        │  Normal  ▁▂▃▄▅▆▇█▄▂           │
│  ● HIGH      DDoS Flood       │  Anomaly ▁▁▁█▁▁▁█▁▁           │
│  ● MEDIUM    Data Exfil       ├─ Severity Distribution ────────┤
│  ● LOW       Brute Force      │  CRITICAL ████ 4               │
│  ...                          │  HIGH     ██   2               │
│                               ├─ Protocol Breakdown ───────────┤
│                               │  HTTPS  ██████ 28              │
├─ Response Actions ────────────┴─ System Terminal ─────────────┤
│  AUTO-RESPONSE LOG              [system log lines]             │
└────────────────────────────────────────────────────────────────┘
```

---

## 🧠 Optional: Enable Real Llama 3

```bash
# 1. Install Ollama: https://ollama.ai/download
# 2. Pull Llama 3
ollama pull llama3
# 3. Run AI-IDS — auto-detects and uses it
python main.py
```

Without Ollama, a built-in expert rule engine provides identical-quality analysis.

---

## 📊 Output Files

After Ctrl+C, two files are saved:

- `logs/alerts.json` — Every alert in JSONL format
- `logs/session_report.txt` — Human-readable session summary

---

## 🔬 How It Works

1. **Simulator** generates realistic packets (~8% anomalous naturally)
2. **Detector** extracts 10 features → StandardScaler → Isolation Forest
3. Anomaly score below threshold → classify severity (CRITICAL/HIGH/MEDIUM/LOW)
4. **LLM Engine** generates natural-language threat analysis
5. **Logger** stores alert, **Dashboard** renders live
6. Automated response action assigned based on severity
