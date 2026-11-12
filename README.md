# AI-IDS — AI-Driven Intrusion Detection System

> A local Python IDS prototype with three separate workflows: **synthetic simulation**, **UNSW-NB15 benchmark evaluation**, and **passive live packet capture**. It combines unsupervised anomaly detection, optional LLM-assisted explanations, and a terminal dashboard.

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Scikit-learn](https://img.shields.io/badge/Scikit--learn-Isolation%20Forest-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![Rich](https://img.shields.io/badge/UI-Rich-111827?style=for-the-badge)](https://rich.readthedocs.io/)
[![Status](https://img.shields.io/badge/Status-Active%20Development-brightgreen?style=for-the-badge)](#status)

AI-IDS is a **research/learning prototype**, not a production network sensor. Choose the simulator for repeatable demonstrations, the separate evaluation module for labeled benchmark metrics, or passive Scapy capture to inspect metadata from an authorized local interface. All three workflows are intentionally distinct.

---

## Why this project?

Signature-based IDS approaches are effective for known patterns, but previously unseen behavior can be harder to detect. This project explores a complementary approach:

```text
Synthetic network traffic
        ↓
Feature extraction
        ↓
Isolation Forest
        ↓
Anomaly score
        ↓
Severity classification
        ↓
LLM / rule-based analysis
        ↓
Alert + dashboard + report
```

The important distinction is that **“zero-day capable” here means anomaly-based detection can flag previously unseen patterns**. It does not mean the system can guarantee detection of every real-world zero-day attack.

---

##  Key Features

| Capability | Implementation |
|---|---|
| 🔍 Anomaly detection | Isolation Forest trained without attack labels |
| 🧪 Attack simulation | Six synthetic attack profiles |
| 🧠 Threat analysis | Optional Ollama/LLM reasoning with local rule-based fallback |
| 📊 Live monitoring | Full-screen Rich terminal dashboard |
| 📈 Feature engineering | 10-dimensional packet-level prototype feature vector (not aggregated flow features) |
| 📝 Alert persistence | JSON/JSONL-style alert logs |
| 📄 Session reporting | Summary generated when monitoring ends |
| 🔄 Model updates | Retraining uses only explicitly trusted-normal samples |

---

##  Live Dashboard

The project includes a terminal-based monitoring interface showing packet counts, alerts, anomaly information, severity distribution, protocol activity, and system status.

<img width="1012" height="571" alt="f485c2b5-3ef7-48fc-9cac-8bbc8b718bdb" src="https://github.com/user-attachments/assets/5692163b-fe1c-4368-9106-eb585b9292a0" />


---

##  Architecture

```text
┌──────────────────────────┐
│     Attack Simulator     │
│ normal + attack traffic  │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│    Feature Extraction    │
│ packet / flow features   │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│    Isolation Forest      │
│ anomaly score + decision │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│  Severity Classification │
│ LOW / MEDIUM / HIGH /    │
│ CRITICAL                 │
└────────────┬─────────────┘
             │
       ┌─────┴─────┐
       ▼           ▼
┌─────────────┐ ┌────────────────┐
│ LLM / Rules │ │ Alert + Logger │
│ explanation │ │ + persistence  │
└──────┬──────┘ └───────┬────────┘
       └───────┬────────┘
               ▼
       ┌────────────────┐
       │ Rich Dashboard │
       │ + Session Report│
       └────────────────┘
```

### Core components

- `simulator.py` — generates normal traffic and synthetic attack scenarios.
- `detector.py` — feature extraction and Isolation Forest anomaly scoring.
- `llm_engine.py` — optional Ollama integration plus deterministic fallback analysis.
- `dashboard.py` — Rich terminal interface.
- `logger.py` — alert persistence and statistics.
- `report.py` — post-session report generation.
- `main.py` — application entry point and CLI; selects simulator or passive capture mode.
- `live_capture.py` — Scapy adapter that extracts packet metadata and payload entropy without retaining payload contents.
- `evaluation/` — isolated UNSW-NB15 benchmark pipeline; it does not feed results into the live detector.

---

##  Detection Pipeline

### 1. Traffic generation

The simulator produces normal traffic patterns such as HTTP, HTTPS, SSH, and DNS alongside controlled attack scenarios. This provides a reproducible environment for demonstrating the detection pipeline.

### 2. Feature extraction

Traffic is represented using features including:

- packet size
- inter-arrival time
- source/destination ports
- TCP flags
- TTL
- payload entropy
- flow duration
- bytes per second
- hour of day

### 3. Isolation Forest

The detector uses an **unsupervised Isolation Forest** model. It is initialized with a synthetic normal-only baseline and assigns anomaly scores to new records. This baseline is a demonstration convenience, not representative training data.

The current configuration uses **150 estimators** and scikit-learn Isolation Forest's `contamination="auto"` threshold. This is a prototype default, not a threshold validated against a representative network dataset.

### 4. Severity classification

Anomaly scores are mapped to application-level severity bands using heuristic cutoffs. These labels are for demonstration triage only; they are not calibrated probabilities or validated risk ratings.

### 5. Threat explanation

Detected anomalies can be passed to Ollama/Llama for human-readable analysis. When Ollama is unavailable, the built-in rule engine provides deterministic fallback explanations.

---

##  Simulated Attack Scenarios

The current simulator includes:

| Scenario | Purpose |
|---|---|
| Port Scan | Detect unusual sequential port activity |
| DDoS Flood | Detect high-volume traffic bursts |
| Data Exfiltration | Detect unusual large outbound transfers |
| Brute Force | Detect rapid authentication attempts |
| C2 Beacon | Detect periodic beacon-like traffic |
| NULL Scan | Detect unusual TCP flag patterns |

These are **synthetic scenarios for experimentation and demonstration**, not evidence of production-world detection performance.

---

##  Evaluation status

**Live detector:** The live Isolation Forest pipeline has **not yet been evaluated on an independent, labeled benchmark dataset**. The dashboard and live session reports therefore do not claim accuracy, F1, or false-positive rate.

**Benchmark harness:** A separate, reproducible UNSW-NB15 evaluation pipeline is available in [`evaluation/`](evaluation/README.md). It can automatically download and checksum-verify the labeled UNSW-NB15 train/test CSVs, cache them locally, then train and calibrate in the offline benchmark workflow and evaluate against the official labeled test split. Run `python -m evaluation.run_unsw_nb15 --download-data`. **Benchmark results have not yet been produced and reviewed**, so no performance metrics are claimed here. The benchmark harness does not train or validate the live detector.

Earlier synthetic comparison charts and confusion matrices remain excluded because they do not independently evaluate the live pipeline.

> **Important:** Synthetic demonstrations exercise the software workflow; they do not establish generalization to real network traffic.

---

##  Technology Stack

| Layer | Technology |
|---|---|
| Language | Python 3.10+ |
| ML | Scikit-learn / Isolation Forest |
| Numerical processing | NumPy |
| Terminal UI | Rich |
| LLM analysis | Ollama / Llama (optional) |
| Persistence | JSON / JSONL-style logs |
| Testing environment | Synthetic network traffic |

---

##  Getting Started

### Requirements

- Python 3.10+
- pip
- Windows, Linux, or macOS

### Installation

```bash
git clone https://github.com/karankr-singh/ai-ids-zero-day-detection.git
cd ai-ids-zero-day-detection

python -m venv .venv
```

Activate the environment:

```bash
# Windows PowerShell
.\.venv\Scripts\Activate.ps1

# Linux / macOS
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the built-in detector tests:

```bash
python -m unittest discover -s tests -v
```

### Optional LLM support

If Ollama is installed and configured with a compatible model, AI-IDS can use it for richer natural-language threat analysis. Otherwise, the built-in fallback engine is used.

---

##  Usage

### 1. Synthetic simulator (default)

This is the original repeatable demo. It generates normal-like records and synthetic attack records; it does **not** sniff your network.

```bash
python main.py --mode simulator
python main.py --mode simulator --demo
python main.py --mode simulator --attack port_scan
```

### 2. Passive live packet capture and baseline learning

Install Scapy (included in `requirements.txt`) and, on Windows, install Npcap. Then list/select a capture interface using your OS/Scapy interface tools and run:

```bash
python main.py --mode live --interface "Wi-Fi" --learn-seconds 30
```

Linux example (use the interface name from `ip link`):

```bash
sudo python main.py --mode live --interface eth0
```

An optional BPF filter can narrow capture, for example:

```bash
python main.py --mode live --interface "Wi-Fi" --bpf-filter "tcp or udp"
```

Live mode is **passive**: it does not inject, block, or modify packets. It extracts IPv4 TCP/UDP metadata and calculates payload entropy in memory; it does not persist or send raw payload bytes to the LLM. Capture only traffic on networks/interfaces you are authorized to monitor. Stop with Ctrl+C.

**Live learning workflow:** live mode starts with a fresh, untrained detector (no synthetic fallback). It passively collects packet metadata for the `--learn-seconds` quiet-window duration (default 30 seconds), requires at least `--min-training-samples` records (default 200), trains on 80% of that window, and calibrates the anomaly-score threshold on the held-out 20%. Keep the network as quiet and representative as possible during learning; avoid downloads, streaming, scans, and other unusual activity. The application cannot prove that this window is attack-free, and the calibration tail is not an independent false-positive-rate measurement. Live anomalies are therefore unclassified, low-priority candidates for review—not confirmed attacks. If the sample minimum is not met, live monitoring does not start and the app does not fall back to the synthetic model. The Scapy adapter maintains lightweight per-5-tuple counters; it is not yet a validated bidirectional flow engine.

### Video demonstration (recommended)

Run a repeatable 32-second sequence showing Port Scan, DDoS Flood, Data Exfiltration, and Brute Force. Each scenario generates 12 synthetic records; the dashboard shows the active scenario, progress, and anomaly-candidate count.

```bash
python main.py --mode simulator --demo --demo-duration 32 --demo-count 12 --speed 8
```

The run is synthetic and demonstrates the application pipeline; it is not proof of real-world attack detection. Press Ctrl+C to stop early. See [VIDEO_DEMO.md](VIDEO_DEMO.md) for the recording setup, suggested narration, and integrity checklist.

### Simulate a specific scenario

```bash
python main.py --attack port_scan
python main.py --attack ddos
python main.py --attack data_exfiltration
python main.py --attack brute_force
python main.py --attack c2_beacon
python main.py --attack null_scan
```

### Control simulator speed

```bash
python main.py --mode simulator --speed 10
```

### 3. Independent benchmark evaluation

The UNSW-NB15 evaluation is a separate offline workflow. Follow [evaluation/README.md](evaluation/README.md); it uses the official labeled train/test files and does not alter the simulator or live-capture model. Do not report benchmark metrics until the run completes and its JSON output has been inspected.

Press **Ctrl+C** to stop a simulator or live-capture session and generate the configured output files.

---

##  Project Structure

```text
ai-ids-zero-day-detection/
├── main.py
├── detector.py
├── simulator.py
├── live_capture.py
├── llm_engine.py
├── logger.py
├── dashboard.py
├── report.py
├── requirements.txt
├── pyproject.toml
├── index.html             # project website
├── VIDEO_DEMO.md          # recording guide and narration
├── evaluation/
│   ├── README.md
│   ├── run_unsw_nb15.py
│   └── __init__.py
├── tests/
│   ├── test_detector.py
│   ├── test_live_baseline.py
│   ├── test_dashboard_scenario.py
│   └── test_evaluation.py
└── logs/                  # generated runtime output (git-ignored)
```

---

##  Output

A monitoring session can produce:

```text
logs/
├── alerts.json
└── session_report.txt
```

These files make it easier to inspect detections after a demonstration or experiment.

---

##  Scope & Limitations

This repository is a **research/academic prototype**. Simulator mode uses synthetic records. Live mode passively captures IPv4 packet metadata through Scapy and starts with a fresh, untrained detector: it learns from an operator-designated quiet window and calibrates a threshold on a held-out portion of that same window; it does **not** use a synthetic baseline or fallback. The learning window is not independently verified as attack-free, and the per-tuple counters are not a validated bidirectional flow detector. A separate UNSW-NB15 benchmark harness is available under `evaluation/`, but benchmark results have not yet been produced and reviewed.

It does **not** provide guaranteed zero-day detection, production-grade incident response, calibrated confidence, or validated enterprise IDS performance. Dashboard response entries are proposed actions only; the application does not block IP addresses, isolate network segments, or modify firewall rules.

Planned areas include:

- calibrated live-mode training using trusted environment-specific normal traffic
- bounded bidirectional flow aggregation and protocol-aware feature validation
- SIEM integrations
- transformer-based detection models
- encrypted traffic analysis
- federated learning experiments
- web-based monitoring
- stronger automated response mechanisms
- containerized deployment

The project is intended for controlled experimentation and learning.

---

##  Related Research Project

### Transformer Zero-Day IDS

[**karankr-singh/transformer-zero-day-ids**](https://github.com/karankr-singh/transformer-zero-day-ids)

The two repositories explore the same broader problem from different angles:

| Repository | Focus |
|---|---|
| **AI-IDS** | Working local prototype, anomaly detection, simulation, dashboard |
| **Transformer Zero-Day IDS** | ML research, Transformer-based detection, dataset evaluation |

---

