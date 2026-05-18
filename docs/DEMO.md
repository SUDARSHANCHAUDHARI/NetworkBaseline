# Demo

Run the included baseline and observed traffic files:

```bash
python3 -m src.anomaly_detector
```

Expected output:

```text
Detected 8 baseline anomaly item(s)
```

Generated artifacts:

- `reports/anomalies.json`
- `reports/summary.json`
- `reports/source-risk.json`
- `reports/baseline-report.md`
- `reports/triage.md`

The sample demonstrates a new external source, unusual ports, and a source-level volume spike.
