# AI-IDS — presentation runbook

## Positioning (say this accurately)

AI-IDS is an academic intrusion-detection prototype exploring unsupervised anomaly scoring. It has three distinct workflows:

1. **Simulator demo** — repeatable synthetic traffic and scripted attack scenarios for demonstrating the application pipeline.
2. **Passive live capture** — Scapy reads authorized IPv4 TCP/UDP packet metadata, learns a local baseline from an operator-designated quiet window, then reports unclassified statistical outliers for review.
3. **Offline UNSW-NB15 evaluation** — a separate Isolation Forest experiment using the official labeled training and test CSVs. It is not the same model instance or feature pipeline as live packet capture.

Do not describe the project as a production IDS or claim that it reliably detects real zero-day attacks. Anomaly scores are not probabilities. Simulator heuristics are not confirmed attack attribution. The app does not block traffic or isolate hosts.

## Before the presentation

- [ ] Pull the latest repository and create a clean Python virtual environment.
- [ ] Install `requirements.txt` and run `python -m unittest discover -s tests -v`.
- [ ] Run the simulator demo once and confirm the dashboard and logs work.
- [ ] Close unrelated apps and use a terminal at least 110 columns wide and 30 rows tall.
- [ ] Increase terminal font size enough for the audience to read the feed.
- [ ] Keep the laptop connected to power and disable notifications.
- [ ] If showing UNSW-NB15 metrics, run the official evaluation beforehand and bring the generated JSON report. Never invent or estimate metrics.

## Recommended 5-minute demo

### 0:00–0:40 — Problem and approach

"Traditional signature matching focuses on known patterns. This prototype explores anomaly-based monitoring: learn a normal-only reference, score incoming records, and surface unusual observations for analyst review."

### 0:40–1:20 — Architecture

Show the repository modules:

- `simulator.py`: generates normal-like and synthetic attack records.
- `detector.py`: extracts packet-level features and scores them with Isolation Forest.
- `llm_engine.py`: optional simulator-mode explanation, with a local deterministic fallback.
- `dashboard.py`: renders the Rich terminal console.
- `logger.py` and `report.py`: persist alerts and session summaries.
- `live_capture.py`: passively extracts packet metadata through Scapy.
- `evaluation/`: separate UNSW-NB15 benchmark path.

### 1:20–3:10 — Live application demo

Run:

```powershell
python main.py --mode simulator --demo
```

Point out:
- packet count and candidate count in the header;
- the alert feed and anomaly score;
- heuristic triage and protocol distribution;
- suggested investigations, with the explicit note that no response is executed;
- system log entries identifying the simulator as the traffic source.

The demo script schedules synthetic port-scan, DDoS-like, data-exfiltration, and brute-force waves. It is a software demonstration, not a network attack and not a benchmark.

### 3:10–4:00 — Evidence and limitations

Open `logs/alerts.json` and `logs/session_report.txt`. Explain that the anomaly ratio is not accuracy. If the official UNSW-NB15 run has completed, show its `unsw_nb15_metrics.json` and explain the normal-only fit/calibration split and untouched official test split. If it has not completed, say so plainly.

### 4:00–5:00 — Next steps

Discuss flow aggregation, richer temporal features, independent validation, threshold stability, and measuring false-positive rates on representative traffic. Avoid claiming that any of these are already solved.

## Optional passive-capture demonstration

Only monitor a network/interface you are authorized to inspect. On Windows, ensure Npcap is installed and the interface name is correct.

```powershell
python main.py --mode live --interface "Wi-Fi" --learn-seconds 30
```

Keep the quiet learning window representative and avoid generating attack traffic during it. The program requires at least 200 records by default. Live alerts are low-priority, unclassified outlier candidates; the capture path does not prove that a candidate is malicious.

## Judge Q&A

**Is this a production-ready IDS?**  
No. It is a research/learning prototype. It demonstrates separate simulator, passive-capture, and offline-evaluation workflows.

**Does it detect zero-day attacks?**  
It explores anomaly-based detection, which can flag behavior not represented in a signature list. That is not a guarantee of zero-day detection. Real-world capability must be established through independent, representative testing.

**How do you know the alert is an attack?**  
A live anomaly is only a statistical outlier against the local baseline. It is not automatically attributed to an attack. The simulator has labels because its records are generated with known scenario labels.

**What is the false-positive rate?**  
Only quote the measured false-positive rate from a completed, documented labeled evaluation. The live calibration tail and simulator alert ratio are not independent FPR measurements.

**Does it block the attacker?**  
No. It is passive and advisory. Suggested actions are not executed.

**Why use Isolation Forest?**  
It is an unsupervised baseline suitable for exploring outlier scoring without attack labels during fitting. It is a starting point, not a claim that it is the best detector for every traffic environment.

## Presentation safety and honesty checklist

- Never call synthetic alert counts "detected real attacks".
- Never call anomaly ratio "accuracy".
- Never present anomaly scores as confidence probabilities.
- Never present proposed responses as actions already taken.
- Distinguish the browser toy demo from the Python detector.
- Distinguish the live-capture model from the separate UNSW-NB15 benchmark model.
