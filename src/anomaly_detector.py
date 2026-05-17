"""Detect traffic that drifts from the baseline."""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
from pathlib import Path

from src.baseline_builder import Baseline, build_baseline
from src.traffic_summary import TrafficEvent, parse_traffic, summarize


@dataclass(frozen=True)
class Anomaly:
    source_ip: str
    destination_ip: str
    destination_port: int
    severity: str
    reason: str


def detect_anomalies(events: list[TrafficEvent], baseline: Baseline) -> list[Anomaly]:
    anomalies: list[Anomaly] = []
    source_counts: dict[str, int] = {}
    for event in events:
        source_counts[event.source_ip] = source_counts.get(event.source_ip, 0) + 1
        if event.source_ip not in baseline.known_sources:
            anomalies.append(Anomaly(event.source_ip, event.destination_ip, event.destination_port, "medium", "new source IP not seen in baseline"))
        if event.destination_port not in baseline.allowed_ports:
            anomalies.append(Anomaly(event.source_ip, event.destination_ip, event.destination_port, "high", "destination port not seen in baseline"))
    for source_ip, count in source_counts.items():
        if count > max(baseline.max_events_per_source * 2, 3):
            anomalies.append(Anomaly(source_ip, "*", 0, "high", f"connection volume {count} exceeds baseline"))
    return anomalies


def build_report(normal: list[TrafficEvent], observed: list[TrafficEvent], anomalies: list[Anomaly]) -> str:
    normal_summary = summarize(normal)
    observed_summary = summarize(observed)
    lines = [
        "# Network Baseline Report",
        "",
        f"- Normal events: {normal_summary['event_count']}",
        f"- Observed events: {observed_summary['event_count']}",
        f"- Anomalies: {len(anomalies)}",
        f"- Observed unique destinations: {observed_summary['unique_destinations']}",
        "",
        "## Anomalies",
        "",
    ]
    if not anomalies:
        lines.append("No baseline drift was detected.")
    for anomaly in anomalies:
        lines.extend(
            [
                f"- **{anomaly.severity}** {anomaly.source_ip} -> {anomaly.destination_ip}:{anomaly.destination_port} - {anomaly.reason}",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Build normal network baseline and flag outliers")
    parser.add_argument("--normal", type=Path, default=Path("data/normal.csv"))
    parser.add_argument("--observed", type=Path, default=Path("data/attack.csv"))
    parser.add_argument("--out", type=Path, default=Path("reports/baseline-report.md"))
    parser.add_argument("--json-out", type=Path, default=Path("reports/anomalies.json"))
    args = parser.parse_args()

    normal = parse_traffic(args.normal)
    observed = parse_traffic(args.observed)
    anomalies = detect_anomalies(observed, build_baseline(normal))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(build_report(normal, observed, anomalies), encoding="utf-8")
    args.json_out.write_text(json.dumps([asdict(item) for item in anomalies], indent=2) + "\n", encoding="utf-8")
    print(f"Detected {len(anomalies)} baseline anomaly item(s)")


if __name__ == "__main__":
    main()
