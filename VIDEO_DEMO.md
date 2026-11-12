# AI-IDS Video Demonstration Guide

## Recommended recording setup

- Use a 16:9 screen recording at 1920×1080 if available.
- Maximize the VS Code terminal panel so the dashboard is readable.
- Use a terminal font size that keeps the complete dashboard visible without scrolling.
- Close unrelated panels and notifications.
- Keep the README or project title visible briefly before launching the demo.

## Run the scripted demonstration

From the repository root:

```powershell
git pull origin main
python -m unittest discover -s tests -v
python main.py --mode simulator --demo --demo-duration 32 --demo-count 12 --speed 8
```

The demo runs four synthetic scenarios in sequence:

| Approx. time | Scenario | What to point out |
|---:|---|---|
| 0–8 s | Port Scan | Scenario name, generated-record counter, candidate counter |
| 9–15 s | DDoS Flood | The scenario changes and the progress indicator resets |
| 16–22 s | Data Exfiltration | Large-transfer synthetic profile and candidate feed |
| 23–31 s | Brute Force | Repeated authentication-attempt synthetic profile |

The exact transition time can vary slightly with machine performance. The dashboard remains active for the configured duration and then prints the session summary.

## Suggested narration

**Opening**

“AI-IDS is a Python-based network intrusion detection prototype. This recording uses its built-in simulator so the same scenarios can be reproduced reliably.”

**During the dashboard**

“The dashboard shows the traffic records being analysed, anomaly candidates, heuristic triage, protocol mix, and suggested investigations. The attack-scenario panel identifies which synthetic scenario is currently being generated and shows its progress and candidate count.”

**Scenario sequence**

“We are demonstrating four controlled synthetic patterns: port scanning, a high-volume flood, unusual outbound data transfer, and repeated authentication attempts. The candidate feed shows what the current prototype flags for review.”

**Closing**

“These are simulator-generated records and heuristic candidate classifications. They demonstrate the application pipeline, not independently validated real-world attack detection. Live passive capture and independent labeled-dataset evaluation are separate workflows.”

## Recording integrity checklist

- Keep the SIMULATOR DEMO indicator visible.
- Do not describe anomaly ratio as accuracy.
- Do not describe heuristic severity as a confirmed threat level.
- Do not claim that the simulator proves zero-day detection.
- Do not hide the model-status or synthetic-data disclaimer.
- If a scenario label or counter is not visible, rerun the demo rather than editing the recording to imply a detection that did not occur.

## If the recording needs another take

Run the command again. The simulator sequence is repeatable in structure, but generated packet values and anomaly counts may vary because packet profiles contain random values.
