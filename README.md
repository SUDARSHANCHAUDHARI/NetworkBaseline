# Network Baseline

[![Python](https://img.shields.io/badge/Python-3.12-blue)](#) [![Status](https://img.shields.io/badge/status-MVP-green)](#) [![Security](https://img.shields.io/badge/security-defensive%20lab-purple)](#)

Lab tool that builds a normal traffic baseline and flags unusual sources, ports, and connection volume.

- **Portfolio group:** Cybersecurity lab project
- **Status:** MVP implemented, tested, committed, and pushed to GitHub
- **GitHub:** https://github.com/SUDARSHANCHAUDHARI/NetworkBaseline
- **Local path:** `/Users/screencloudsudarshan/SUDARSHAN_CODE/sudarshan_repos/CyberSecurity/NetworkBaseline`

## MVP Snapshot

This repository includes a working MVP with safe sample data, deterministic detection or analysis logic, local tests, and generated output reports where relevant. It is ready for README/demo polish or deeper product work.

## Safe Use

This project is defensive and analysis-focused. Use only with logs, systems, repositories, and lab environments you own or have permission to assess.

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

## Roadmap

- Polish sample output screenshots or terminal demos
- Add architecture diagram and deeper implementation notes
- Expand test coverage around edge cases
- Add Docker or local demo workflow where useful
- Prepare `v0.1.0-mvp` release notes
