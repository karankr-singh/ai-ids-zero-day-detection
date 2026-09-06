# 🛡️ AI-IDS — AI-Driven Intrusion Detection System

> A local Python IDS prototype combining **unsupervised anomaly detection**, **LLM-assisted threat analysis**, attack simulation, and a live terminal dashboard.

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Scikit-learn](https://img.shields.io/badge/Scikit--learn-Isolation%20Forest-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![Rich](https://img.shields.io/badge/UI-Rich-111827?style=for-the-badge)](https://rich.readthedocs.io/)
[![Status](https://img.shields.io/badge/Status-Active%20Development-brightgreen?style=for-the-badge)](#status)

AI-IDS is designed as a **working cybersecurity/ML prototype** rather than a production network sensor. It generates synthetic traffic and attack scenarios, extracts behavioral features, scores anomalies with Isolation Forest, enriches alerts with an optional local LLM, and presents the results through a Rich-based terminal interface.

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

## ✨ Key Features

| Capability | Implementation |
|---|---|
| 🔍 Anomaly detection | Isolation Forest trained without attack labels |
| 🧪 Attack simulation | Six synthetic attack profiles |
| 🧠 Threat analysis | Optional Ollama/LLM reasoning with local rule-based fallback |
| 📊 Live monitoring | Full-screen Rich terminal dashboard |
| 📈 Feature engineering | 10-dimensional packet/flow feature representation |
| 📝 Alert persistence | JSON/JSONL-style alert logs |
| 📄 Session reporting | Summary generated when monitoring ends |
| 🔄 Model updates | Retraining support using accumulated traffic data |

---

## 🎬 Live Dashboard

The project includes a terminal-based monitoring interface showing packet counts, alerts, anomaly information, severity distribution, protocol activity, and system status.

<img width="996" height="293" alt="AI-IDS live terminal dashboard" src="https://github.com/user-attachments/assets/048c3640-1aad-4bd6-86d9-c6148e4c600c" />

---

## 🏗️ Architecture

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
- `main.py` — application entry point and CLI.

---

## 🔬 Detection Pipeline

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

The detector uses an **unsupervised Isolation Forest** model. It learns the structure of the supplied traffic and assigns anomaly scores to new observations.

The current configuration uses **150 estimators** and an **8% contamination setting** in the prototype.

### 4. Severity classification

Anomaly scores are mapped to application-level severity bands, which are then surfaced in the dashboard and logs.

### 5. Threat explanation

Detected anomalies can be passed to Ollama/Llama for human-readable analysis. When Ollama is unavailable, the built-in rule engine provides deterministic fallback explanations.

---

## 🎯 Simulated Attack Scenarios

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

## 📊 Evaluation

The repository includes experiments comparing model behavior and visualizing results.

<img width="750" height="600" alt="AI-IDS confusion matrix" src="https://github.com/user-attachments/assets/8c470c99-1575-42b6-975b-bc4bdb71de18" />

<img width="1800" height="900" alt="AI-IDS model comparison" src="https://github.com/user-attachments/assets/a831e35f-278d-4c51-911e-bf5d3ec54519" />

> **Important:** Reported detection rates and accuracy values are based on the project's synthetic test setup. They should not be interpreted as benchmarks on real enterprise traffic.

---

## 🛠️ Technology Stack

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

## 🚀 Getting Started

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

### Optional LLM support

If Ollama is installed and configured with a compatible model, AI-IDS can use it for richer natural-language threat analysis. Otherwise, the built-in fallback engine is used.

---

## ▶️ Usage

### Live monitoring

```bash
python main.py
```

### Demonstration mode

```bash
python main.py --demo
```

### Simulate a specific scenario

```bash
python main.py --attack port_scan
python main.py --attack ddos
python main.py --attack data_exfiltration
python main.py --attack brute_force
python main.py --attack c2_beacon
python main.py --attack null_scan
```

### Control simulation speed

```bash
python main.py --speed 10
```

Press **Ctrl+C** to stop the session and generate the configured output files.

---

## 📁 Project Structure

```text
ai-ids-zero-day-detection/
├── main.py
├── detector.py
├── simulator.py
├── llm_engine.py
├── logger.py
├── dashboard.py
├── report.py
├── requirements.txt
└── logs/                 # generated runtime output
```

---

## 📦 Output

A monitoring session can produce:

```text
logs/
├── alerts.json
└── session_report.txt
```

These files make it easier to inspect detections after a demonstration or experiment.

---

## ⚠️ Scope & Limitations

This repository is a **research/academic prototype**. It currently relies on simulated traffic rather than passive capture from a production network.

It does **not** provide guaranteed zero-day detection, production-grade incident response, or validated enterprise IDS performance.

Planned areas include:

- real packet capture using Scapy/Wireshark integrations
- SIEM integrations
- transformer-based detection models
- encrypted traffic analysis
- federated learning experiments
- web-based monitoring
- stronger automated response mechanisms
- containerized deployment

The project is intended for controlled experimentation and learning.

---

## 🔗 Related Research Project

### Transformer Zero-Day IDS

[**karankr-singh/transformer-zero-day-ids**](https://github.com/karankr-singh/transformer-zero-day-ids)

The two repositories explore the same broader problem from different angles:

| Repository | Focus |
|---|---|
| **AI-IDS** | Working local prototype, anomaly detection, simulation, dashboard |
| **Transformer Zero-Day IDS** | ML research, Transformer-based detection, dataset evaluation |

---

## 👥 Contributors

- **Karan Kumar Singh** — Developer & Researcher
- **Kaushik Sheregar** — Developer & Researcher
- **Dr. Saneh Lata Yadav** — Faculty Mentor

---

## 📄 License

See the repository for licensing information.
