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
    kind: str
    reason: str
    recommendation: str


def make_anomaly(source_ip: str, destination_ip: str, destination_port: int, severity: str, kind: str, reason: str) -> Anomaly:
    recommendations = {
        "baseline.new_source": "Confirm whether this source is expected, then add to baseline or investigate the host.",
        "baseline.new_port": "Review the destination service and verify whether this port should be allowed.",
        "baseline.new_destination": "Confirm the destination belongs to expected infrastructure.",
        "baseline.volume_spike": "Check whether this is an authorized batch job, scan, or compromised host.",
    }
    return Anomaly(source_ip, destination_ip, destination_port, severity, kind, reason, recommendations[kind])


def detect_anomalies(events: list[TrafficEvent], baseline: Baseline) -> list[Anomaly]:
    anomalies: list[Anomaly] = []
    source_counts: dict[str, int] = {}
    for event in events:
        source_counts[event.source_ip] = source_counts.get(event.source_ip, 0) + 1
        if event.source_ip not in baseline.known_sources:
            anomalies.append(
                make_anomaly(
                    event.source_ip,
                    event.destination_ip,
                    event.destination_port,
                    "medium",
                    "baseline.new_source",
                    "new source IP not seen in baseline",
                )
            )
        if event.destination_port not in baseline.allowed_ports:
            anomalies.append(
                make_anomaly(
                    event.source_ip,
                    event.destination_ip,
                    event.destination_port,
                    "high",
                    "baseline.new_port",
                    "destination port not seen in baseline",
                )
            )
        if event.destination_ip not in baseline.known_destinations:
            anomalies.append(
                make_anomaly(
                    event.source_ip,
                    event.destination_ip,
                    event.destination_port,
                    "medium",
                    "baseline.new_destination",
                    "destination IP not seen in baseline",
                )
            )
    for source_ip, count in source_counts.items():
        if count >= max(baseline.max_events_per_source * 2, 3):
            anomalies.append(
                make_anomaly(
                    source_ip,
                    "*",
                    0,
                    "high",
                    "baseline.volume_spike",
                    f"connection volume {count} exceeds baseline",
                )
            )
    return anomalies


def build_source_risk(observed: list[TrafficEvent], anomalies: list[Anomaly]) -> list[dict]:
    """Return source-level drift rows for triage."""
    rows = []
    sources = {event.source_ip for event in observed} | {anomaly.source_ip for anomaly in anomalies}
    for source_ip in sorted(sources):
        source_events = [event for event in observed if event.source_ip == source_ip]
        source_anomalies = [anomaly for anomaly in anomalies if anomaly.source_ip == source_ip]
        rows.append(
            {
                "source_ip": source_ip,
                "events": len(source_events),
                "anomalies": len(source_anomalies),
                "max_severity": "high" if any(item.severity == "high" for item in source_anomalies) else ("medium" if source_anomalies else "low"),
                "destinations": sorted({event.destination_ip for event in source_events}),
                "ports": sorted({event.destination_port for event in source_events}),
                "anomaly_types": sorted({item.kind for item in source_anomalies}),
            }
        )
    order = {"high": 3, "medium": 2, "low": 1}
    return sorted(rows, key=lambda row: (-order[row["max_severity"]], -row["anomalies"], row["source_ip"]))


def build_summary(normal: list[TrafficEvent], observed: list[TrafficEvent], anomalies: list[Anomaly]) -> dict:
    """Return dashboard-friendly baseline summary."""
    normal_summary = summarize(normal)
    observed_summary = summarize(observed)
    return {
        "normal_events": normal_summary["event_count"],
        "observed_events": observed_summary["event_count"],
        "normal_unique_destinations": normal_summary["unique_destinations"],
        "observed_unique_destinations": observed_summary["unique_destinations"],
        "anomalies": len(anomalies),
        "high": sum(1 for anomaly in anomalies if anomaly.severity == "high"),
        "medium": sum(1 for anomaly in anomalies if anomaly.severity == "medium"),
    }


def build_report(normal: list[TrafficEvent], observed: list[TrafficEvent], anomalies: list[Anomaly]) -> str:
    summary = build_summary(normal, observed, anomalies)
    source_risk = build_source_risk(observed, anomalies)
    lines = [
        "# Network Baseline Report",
        "",
        f"- Normal events: {summary['normal_events']}",
        f"- Observed events: {summary['observed_events']}",
        f"- Anomalies: {summary['anomalies']}",
        f"- High severity: {summary['high']}",
        f"- Medium severity: {summary['medium']}",
        f"- Observed unique destinations: {summary['observed_unique_destinations']}",
        "",
        "## Source Risk",
        "",
    ]
    for row in source_risk:
        types = ", ".join(row["anomaly_types"]) if row["anomaly_types"] else "none"
        lines.append(f"- `{row['source_ip']}`: {row['max_severity']}, anomalies={row['anomalies']}, types={types}")
    lines.extend(
        [
            "",
            "## Anomalies",
            "",
        ]
    )
    if not anomalies:
        lines.append("No baseline drift was detected.")
    for anomaly in anomalies:
        lines.extend(
            [
                f"### {anomaly.source_ip} -> {anomaly.destination_ip}:{anomaly.destination_port}",
                "",
                f"- Severity: `{anomaly.severity}`",
                f"- Type: `{anomaly.kind}`",
                f"- Reason: {anomaly.reason}",
                f"- Recommended next step: {anomaly.recommendation}",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def build_triage_report(summary: dict, source_risk: list[dict], anomalies: list[Anomaly]) -> str:
    """Return compact triage report."""
    lines = [
        "# Network Baseline Triage",
        "",
        f"- Observed events: {summary['observed_events']}",
        f"- Anomalies: {summary['anomalies']}",
        "",
        "## Source Risk",
        "",
    ]
    for row in source_risk:
        lines.append(
            f"- `{row['source_ip']}`: {row['max_severity']}, events={row['events']}, anomalies={row['anomalies']}"
        )
    lines.extend(["", "## Analyst Queue", ""])
    if not anomalies:
        lines.append("- No immediate analyst queue was generated.")
    for anomaly in anomalies[:8]:
        lines.append(f"- `{anomaly.severity}` {anomaly.kind}: {anomaly.source_ip} -> {anomaly.destination_ip}:{anomaly.destination_port}")
    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Build normal network baseline and flag outliers")
    parser.add_argument("--normal", type=Path, default=Path("data/normal.csv"))
    parser.add_argument("--observed", type=Path, default=Path("data/attack.csv"))
    parser.add_argument("--out", type=Path, default=Path("reports/baseline-report.md"))
    parser.add_argument("--json-out", type=Path, default=Path("reports/anomalies.json"))
    parser.add_argument("--summary-out", type=Path, default=Path("reports/summary.json"))
    parser.add_argument("--source-risk-out", type=Path, default=Path("reports/source-risk.json"))
    parser.add_argument("--triage-out", type=Path, default=Path("reports/triage.md"))
    args = parser.parse_args()

    normal = parse_traffic(args.normal)
    observed = parse_traffic(args.observed)
    anomalies = detect_anomalies(observed, build_baseline(normal))
    summary = build_summary(normal, observed, anomalies)
    source_risk = build_source_risk(observed, anomalies)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(build_report(normal, observed, anomalies), encoding="utf-8")
    args.json_out.write_text(json.dumps([asdict(item) for item in anomalies], indent=2) + "\n", encoding="utf-8")
    args.summary_out.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    args.source_risk_out.write_text(json.dumps(source_risk, indent=2) + "\n", encoding="utf-8")
    args.triage_out.write_text(build_triage_report(summary, source_risk, anomalies), encoding="utf-8")
    print(f"Detected {len(anomalies)} baseline anomaly item(s)")


if __name__ == "__main__":
    main()
