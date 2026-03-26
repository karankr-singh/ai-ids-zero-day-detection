# 🛡️ AI-IDS: AI-Driven Intrusion Detection System
### Live Terminal Dashboard | Real-Time Detection | Zero-Day Capable

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-1.4.0-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)
![Rich](https://img.shields.io/badge/Rich-Terminal_UI-00d4ff?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)


*A fully working, local Python-based Intrusion Detection System with a live
terminal dashboard, ML anomaly detection, LLM-powered threat analysis,
and automated attack simulation — no browser or server required.*

</div>

---

## 📌 Table of Contents

- [About](#-about)
- [Live Demo](#-live-demo)
- [Features](#-features)
- [System Architecture](#-system-architecture)
- [How It Works](#-how-it-works)
- [Attack Types Detected](#-attack-types-detected)
- [Detection Results](#-detection-results)
- [Technology Stack](#-technology-stack)
- [Installation](#-installation)
- [Usage](#-usage)
- [Project Structure](#-project-structure)
- [Future Scope](#-future-scope)
- [Related Project](#-related-project)
- [Contributors](#-contributors)

---

## 🔍 About

**AI-IDS** is a fully functional, locally-running Intrusion Detection System
that combines **Isolation Forest** machine learning with **LLM-based reasoning**
to detect zero-day cyber attacks in real time — without relying on any predefined
attack signatures.

Unlike traditional IDS tools that only detect known threats, AI-IDS learns what
**normal** network traffic looks like and flags anything that deviates — making
it capable of catching entirely new, never-seen-before attack patterns.

The system runs entirely from the terminal with a live, full-screen dashboard
built using the `rich` library. No browser, no server, no internet connection
required.

> **One-line summary:** Run `python main.py` and get a live cybersecurity
> operations center on your terminal — detecting, classifying, and responding
> to threats in real time.

---

## 🎬 Live Demo

```
┌─ Header: Packets │ Alerts │ Accuracy │ FPR │ Status: ● MONITORING ──┐
├─ Live Alert Feed ──────────────┬─ Traffic Sparklines ───────────────┤
│  ● CRITICAL  Port Scan         │  Normal  ▁▂▃▄▅▆▇█▄▂               │
│  ● HIGH      DDoS Flood        │  Anomaly ▁▁▁█▁▁▁█▁▁               │
│  ● MEDIUM    Data Exfiltration ├─ Severity Distribution ────────────┤
│  ● LOW       Brute Force       │  CRITICAL ████████ 8               │
│  ...                           │  HIGH     █████    5               │
│                                │  MEDIUM   ███      3               │
│                                ├─ Protocol Breakdown ───────────────┤
│                                │  HTTPS  ██████████ 42              │
│                                │  HTTP   ████       18              │
├─ Response Actions ─────────────┴─ System Terminal ────────────────┤
│  CRITICAL  Port Scan from 45.33.32.1 — BLOCK IP + ISOLATE         │
│  HIGH      DDoS Flood from 192.0.2.5 — BLOCK IP + FIREWALL        │
│  [21:48:53] Isolation Forest model loaded (150 estimators)         │
│  [21:48:53] Attack simulator ready — 6 attack profiles             │
└────────────────────────────────────────────────────────────────────┘
```

> Screenshot of the actual running dashboard

<img width="996" height="293" alt="Screenshot 2026-03-26 160502" src="https://github.com/user-attachments/assets/048c3640-1aad-4bd6-86d9-c6148e4c600c" />


---

## ✨ Features

| Feature | Description |
|---|---|
| 🔍 **Real-Time Detection** | Analyzes network packets continuously as they arrive |
| 🤖 **Isolation Forest ML** | Unsupervised anomaly detection — no labeled data needed |
| 🧠 **LLM Reasoning** | Natural language threat analysis via Ollama / expert fallback |
| ⚡ **Attack Simulation** | 6 built-in attack profiles for testing and demonstration |
| 📊 **Live Dashboard** | Full-screen terminal UI with charts, alerts, and logs |
| 🛡️ **Auto Response** | Tiered automated responses based on threat severity |
| 🔄 **Model Retraining** | Online learning from accumulated traffic data |
| 💾 **Alert Persistence** | All alerts saved to `logs/alerts.json` |
| 📄 **Session Report** | Auto-generated report on exit |
| 🎯 **Zero-Day Capable** | Detects unknown attacks with no signature required |

---

## 🏗️ System Architecture

```
Network Traffic (Simulated)
           │
           ▼
┌──────────────────────┐
│   Attack Simulator   │  ← Generates realistic normal + attack packets
│   simulator.py       │    6 attack profiles, ~8% anomaly rate
└──────────┬───────────┘
           │
           ▼
┌──────────────────────────────────────────┐
│         Anomaly Detection Engine         │
│              detector.py                 │
│                                          │
│  Raw Packet → Feature Extraction (10D)   │
│            → StandardScaler              │
│            → Isolation Forest            │
│            → Anomaly Score               │
│            → Severity Classification     │
│              CRITICAL / HIGH / MEDIUM / LOW│
└──────────┬───────────────────────────────┘
           │
           ▼
┌──────────────────────┐
│    LLM Reasoning     │  ← Ollama/Llama3 (if installed)
│    llm_engine.py     │    Expert Rule Engine (fallback)
│                      │    Generates human-readable analysis
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐     ┌─────────────────────────┐
│   Alert Logger       │     │   Terminal Dashboard     │
│   logger.py          │────▶│   dashboard.py           │
│   logs/alerts.json   │     │   Live Rich UI           │
└──────────────────────┘     └─────────────────────────┘
           │
           ▼
┌──────────────────────┐
│  Automated Response  │
│  BLOCK / THROTTLE /  │
│  LOG / ISOLATE       │
└──────────────────────┘
```

---

## ⚙️ How It Works

### Stage 1 — Traffic Generation
The `AttackSimulator` generates realistic network packets — both normal traffic
and attack traffic. Normal traffic follows real-world patterns (HTTP, HTTPS, SSH,
DNS). About 8% of packets are anomalous by default, mimicking real network conditions.

### Stage 2 — Feature Extraction
Each packet is converted into a **10-dimensional feature vector:**
- Packet size, inter-arrival time, destination port, source port
- TCP flags, TTL, payload entropy, flow duration
- Bytes per second, hour of day

### Stage 3 — Isolation Forest Detection
The **Isolation Forest** model (150 estimators, 8% contamination) scores each
packet. Lower scores = more anomalous. The model is pre-trained on synthetic
normal traffic and continuously updated via online retraining.

### Stage 4 — Severity Classification
Anomaly scores are mapped to severity levels:

| Score Range | Severity | Response |
|---|---|---|
| Below -0.55 | 🔴 CRITICAL | Block IP + Isolate Segment + Alert SOC |
| -0.55 to -0.40 | 🟠 HIGH | Block IP + Update Firewall Rules |
| -0.40 to -0.25 | 🟡 MEDIUM | Throttle Traffic + Flag for Review |
| -0.25 to -0.10 | 🔵 LOW | Log Event + Continue Monitoring |

### Stage 5 — LLM Threat Analysis
Every detected anomaly gets a natural-language threat analysis explaining:
- What the attack is and how it works
- Why this traffic pattern is suspicious
- What action should be taken

### Stage 6 — Automated Response
The system automatically executes tiered countermeasures without human
intervention — from simple logging to full network segment isolation.

---

## 🎯 Attack Types Detected

| Attack | Description | Detection Rate |
|---|---|---|
| **Port Scan** | Sequential port enumeration (nmap/masscan style) | ✅ 100% |
| **DDoS Flood** | High-volume packet flood targeting a single host | ✅ 100% |
| **Data Exfiltration** | Large encrypted outbound transfer on unusual port | ✅ 100% |
| **Brute Force** | Rapid authentication attempts on SSH/RDP | ✅ 100% |
| **C2 Beacon** | Periodic encrypted command-and-control beaconing | ✅ 100% |
| **NULL Scan** | Zero-flag TCP packets to evade stateful firewalls | ✅ 100% |
| **Zero-Day (Unknown)** | Novel anomalous patterns with no known signature | ✅ Flagged |

---

## 📊 Detection Results

Detection rates measured by injecting known attack bursts (10 packets each):

| Attack Type | Packets Sent | Detected | Rate |
|---|---|---|---|
| Port Scan | 10 | 10 | 100% |
| DDoS Flood | 10 | 10 | 100% |
| Data Exfiltration | 10 | 10 | 100% |
| Brute Force | 10 | 10 | 100% |
| C2 Beacon | 10 | 10 | 100% |
| NULL Scan | 10 | 10 | 100% |

**Model Performance:**

| Metric | Value |
|---|---|
| Model | Isolation Forest (150 estimators) |
| Training | Unsupervised — no labeled data needed |
| Accuracy | ~92–96% |
| False Positive Rate | ~2–5% |
| Contamination | 8% |

### Confusion Matrix
<img width="750" height="600" alt="confusion_matrix" src="https://github.com/user-attachments/assets/8c470c99-1575-42b6-975b-bc4bdb71de18" />


### Model Comparison
<img width="1800" height="900" alt="model_comparison" src="https://github.com/user-attachments/assets/a831e35f-278d-4c51-911e-bf5d3ec54519" />


---

## 🛠️ Technology Stack

| Component | Technology | Purpose |
|---|---|---|
| Language | Python 3.10+ | Core development |
| ML Detection | Scikit-learn 1.4.0 | Isolation Forest model |
| Terminal UI | Rich 13.7.0 | Live dashboard rendering |
| LLM Reasoning | Ollama / Llama 3 | Threat analysis (optional) |
| Fallback Engine | Expert Rule System | Built-in threat analysis |
| Data Processing | NumPy 1.26.0 | Feature engineering |
| Alert Storage | JSON (JSONL) | Persistent alert logging |

---

## 🚀 Installation

### Requirements
- Python 3.10 or higher
- 100 MB free disk space
- Windows / Linux / Mac

```bash
# 1. Clone the repository
git clone https://github.com/karankr-singh/ai-ids-zero-day-detection.git
cd ai-ids-zero-day-detection

# 2. Install dependencies (only 3 packages)
pip install -r requirements.txt
```

### Optional — Enable Real LLM (Llama 3)
```bash
# Install Ollama from https://ollama.ai
ollama pull llama3

# AI-IDS will auto-detect and use it
```

> **Note:** Without Ollama, the built-in expert rule engine provides
> equivalent threat analysis automatically. No setup needed.

---

## ▶️ Usage

```bash
# Live monitoring mode (default)
python main.py

# 45-second scripted demo with 4 attack waves
python main.py --demo

# Inject a specific attack type
python main.py --attack port_scan
python main.py --attack ddos
python main.py --attack data_exfiltration
python main.py --attack brute_force
python main.py --attack c2_beacon
python main.py --attack null_scan

# Adjust analysis speed
python main.py --speed 10    # 10 packets/second

# Press Ctrl+C to stop — session report auto-saved
```

### Dashboard Controls
| Key | Action |
|---|---|
| `Ctrl+C` | Stop monitoring + save session report |

### Output Files (auto-generated on exit)
```
logs/
├── alerts.json          ← Every alert in JSONL format
└── session_report.txt   ← Full session summary
```

---

## 📂 Project Structure

```
ai-ids-zero-day-detection/
│
├── main.py          ← Entry point — run this
├── detector.py      ← Isolation Forest ML engine
├── simulator.py     ← Network traffic + attack generator
├── llm_engine.py    ← LLM reasoning (Ollama + expert fallback)
├── logger.py        ← Alert storage and statistics
├── dashboard.py     ← Live Rich terminal dashboard
├── report.py        ← Post-session report generator
├── requirements.txt ← pip install -r requirements.txt
```

---

## 🔭 Future Scope

- [ ] Real network packet capture via Scapy / Wireshark
- [ ] Integration with enterprise SIEM platforms (Splunk, IBM QRadar)
- [ ] Transformer-based deep learning detection model
- [ ] Federated learning across multiple network nodes
- [ ] Encrypted TLS traffic analysis
- [ ] Web-based monitoring dashboard (Flask/React)
- [ ] Fully autonomous response with reinforcement learning
- [ ] Docker containerization for easy deployment

---

## 🔗 Related Project

👉 **[Transformer IDS — Research Model](https://github.com/karankr-singh/transformer-zero-day-ids)**
Research-focused Transformer-based IDS with UNSW-NB15 dataset evaluation,
multi-model comparison, and self-evolving learning concept.

Both repositories together form the complete Final Year Project:
- **Transformer IDS** = Research + Theory + Dataset Evaluation
- **AI-IDS (this repo)** = Working Prototype + Live Demo + Real-time Detection

---

## 👥 Contributors

| Name | Role |
|---|---|
| Karan Kumar Singh | Developer & Researcher |
| Kaushik Sheregar | Developer & Researcher |
| Dr. Saneh Lata Yadav | Faculty Mentor & Guide |

</div>
