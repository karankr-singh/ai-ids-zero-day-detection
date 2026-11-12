# AI-IDS video demonstration guide

This guide keeps synthetic demonstration, passive live capture, and offline
benchmark results clearly separated. Do not present simulated packets as
real network traffic or benchmark metrics as live-capture performance.

## 1. Prepare the environment

```powershell
git pull origin main
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

For the held-out category evaluation, run:

```powershell
python -m evaluation.run_unseen_attacks --download-data
```

Review `results/unsw_nb15/unsw_nb15_unseen_categories.json` before recording
the evaluation segment. Report each category's test sample count with recall.
Do not invent or round metrics beyond what the JSON contains.

## 2. Record the repeatable simulator demonstration

```powershell
python main.py --mode simulator --demo --demo-duration 32 --demo-count 12 --speed 8
```

This sequence generates four synthetic scenarios: Port Scan, DDoS Flood,
Data Exfiltration, and Brute Force. The dashboard labels the source as
`SIMULATOR DEMO`. Explain that this demonstrates the software pipeline,
not real packet capture or independently validated attack detection.

## 3. Optional: record passive live capture separately

On Windows, install Npcap and run PowerShell as Administrator. Identify the
correct interface name, then run:

```powershell
python main.py --mode live --interface "Wi-Fi" --learn-seconds 30
```

Use an interface you are authorized to monitor. Keep the learning interval
quiet and representative. The application cannot verify that the learning
window is attack-free. If it does not capture the configured minimum number
of samples, it will stop rather than use the simulator baseline.

Live mode is passive and advisory. It captures packet metadata, not raw
payloads; it does not inject packets, block traffic, or isolate a network.
The detector's live baseline is separate from the UNSW-NB15 benchmark model.

## 4. Suggested 3–4 minute narration

1. **Problem and goal (20 s):** Explain why signature-only detection can miss
   previously unseen behavior and introduce anomaly detection as a research
   approach.
2. **Architecture (30 s):** Show packet metadata → feature extraction →
   Isolation Forest → candidate alert → analyst review.
3. **Simulator demo (60–75 s):** Run the four scripted synthetic scenarios.
   Point out the source mode and explain that the traffic is generated.
4. **Live capture (30–45 s, optional):** Show the separate passive capture
   mode and its operator-designated baseline learning. Do not stage an attack
   on a network you do not own or administer.
5. **Benchmark (40–50 s):** Show the UNSW-NB15 benchmark and unseen-category
   JSON results. Explain the fit/calibration/test separation and report
   precision, recall, F1, FPR, and per-category sample counts together.
6. **Limitations and next steps (15–20 s):** State that anomaly candidates
   require analyst review, category holdout is dataset-specific, and the
   prototype does not provide network-segment isolation.

## 5. Integrity checklist

- [ ] Simulator and live-capture recordings are clearly labeled.
- [ ] Dashboard packet and candidate counts come from the running process.
- [ ] No synthetic metrics or fabricated confidence values are shown.
- [ ] Benchmark metrics are read from the generated JSON result files.
- [ ] Per-category recall is shown with its sample count.
- [ ] No claim of guaranteed or universal zero-day detection is made.
- [ ] No claim of automatic network blocking or segment isolation is made.
