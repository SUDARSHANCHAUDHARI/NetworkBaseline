# Network Baseline

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](#requirements)
[![Status](https://img.shields.io/badge/status-MVP-green)](#status)
[![Security](https://img.shields.io/badge/security-defensive%20lab-purple)](#safe-use)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Builds a normal traffic baseline from a sample of network logs, then flags unusual source IPs, destination ports, and connection volume spikes in observed traffic.

---

## Overview

Network Baseline is a defensive analysis lab tool that takes a "normal" sample of network connections, learns typical source IPs, destination ports, and per-host volume, and compares it against an "observed" sample to detect anomalies. Outputs include severity-scored anomalies, per-source risk tables, and an analyst triage handoff.

## Features

- Parses CSV network traffic logs
- Builds normal baseline (source IPs, destination ports, volume)
- Detects new source IPs not seen in baseline
- Detects connections to unexpected destination ports
- Detects volume spikes (per-source request bursts)
- Severity-scores each anomaly
- Outputs JSON anomalies, source risk, summary, Markdown report, and triage handoff

## Requirements

- Python 3.10 or newer
- Linux, macOS, or Windows
- No third-party Python packages (standard library only)
- Optional: Docker for the demo container

## Installation

```bash
git clone https://github.com/SUDARSHANCHAUDHARI/NetworkBaseline.git
cd NetworkBaseline
pip install .
```

This registers the `network-baseline` CLI command.

To run without installing:

```bash
python3 main.py --help
```

## Usage

Compare normal vs attack-sample traffic using the included data:

```bash
python3 main.py --normal data/normal.csv --observed data/attack.csv --out reports/baseline-report.md
```

Generated outputs in `reports/`:

- `baseline-report.md` — Markdown anomaly report
- `anomalies.json` — structured anomaly findings
- `summary.json` — counts and severity breakdown
- `source-risk.json` — per-source risk table
- `triage.md` — analyst triage checklist

## Project Structure

```
NetworkBaseline/
├── src/            Parser, baseline builder, anomaly detector, traffic summary
├── data/           Safe sample CSVs (normal + attack)
├── reports/        Example generated output
├── docker/         Dockerfile + compose support
├── docs/           Architecture, security notes, demo
├── tests/          Unit tests
├── main.py         CLI entrypoint
├── pyproject.toml  Package metadata
└── LICENSE
```

## Testing

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```

## Docker Demo

```bash
docker compose run --rm network-baseline-demo
```

## Safe Use

This project is defensive and analysis-focused. Use only with logs and lab environments you own or have explicit written permission to assess. The included sample CSVs are synthetic and safe for public demo use.

## Status

Working CLI MVP with tests, sample data, and Docker support.

## Roadmap

- Streaming mode for live capture
- pcap and JSONL log support
- Time-of-day baseline (different normal per hour)
- Configurable severity thresholds
- GitHub release `v0.1.0-mvp`

## License

Released under the [MIT License](LICENSE). You are free to use, modify, and distribute this software with attribution.

## Author

**Sudarshan Chaudhari** — [SudarshanTechLabs](https://github.com/SUDARSHANCHAUDHARI)
Bangkok, Thailand

For inquiries: open an issue on [GitHub](https://github.com/SUDARSHANCHAUDHARI/NetworkBaseline/issues).
