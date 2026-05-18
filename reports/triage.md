# Network Baseline Triage

- Observed events: 5
- Anomalies: 8

## Source Risk

- `198.51.100.80`: high, events=4, anomalies=8
- `10.0.0.10`: low, events=1, anomalies=0

## Analyst Queue

- `medium` baseline.new_source: 198.51.100.80 -> 10.0.0.20:4444
- `high` baseline.new_port: 198.51.100.80 -> 10.0.0.20:4444
- `medium` baseline.new_source: 198.51.100.80 -> 10.0.0.20:8080
- `high` baseline.new_port: 198.51.100.80 -> 10.0.0.20:8080
- `medium` baseline.new_source: 198.51.100.80 -> 10.0.0.20:3389
- `high` baseline.new_port: 198.51.100.80 -> 10.0.0.20:3389
- `medium` baseline.new_source: 198.51.100.80 -> 10.0.0.20:22
- `high` baseline.volume_spike: 198.51.100.80 -> *:0
