# Network Baseline

**Goal:** Understand normal vs abnormal traffic.

**MVP:** Create baseline from normal traffic, flag outliers.

## Core Features

- traffic summary
- top IPs
- top ports
- unusual connection volume
- baseline comparison

## Quick Start

```bash
python3 -m src.anomaly_detector
python3 -m unittest discover -s tests -p 'test_*.py'
```

## MVP Capabilities

- Builds a baseline from normal traffic
- Summarizes top IPs, ports, and destinations
- Detects new source IPs
- Detects destination ports outside the baseline
- Detects unusual connection volume
- Writes Markdown and JSON reports

## Repository Status

This repository contains a working Network Baseline MVP with safe traffic samples, outlier detection, generated reports, and tests.

## Production Foundation

- Private GitHub repository linked to `main`
- Initial MVP scaffold committed
- CI repository-health workflow
- Security policy
- Contribution guide
- Pull request and issue templates
- Production readiness checklist
- Safe ignore rules for local secrets and generated files
