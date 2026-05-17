"""Traffic parsing and summaries for Network Baseline."""

from __future__ import annotations

import csv
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


@dataclass(frozen=True)
class TrafficEvent:
    timestamp: datetime
    source_ip: str
    destination_ip: str
    destination_port: int
    protocol: str


def parse_traffic(path: Path) -> list[TrafficEvent]:
    with path.open(encoding="utf-8", newline="") as handle:
        return [
            TrafficEvent(
                timestamp=datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00")),
                source_ip=row["source_ip"],
                destination_ip=row["destination_ip"],
                destination_port=int(row["destination_port"]),
                protocol=row["protocol"].upper(),
            )
            for row in csv.DictReader(handle)
            if row.get("timestamp")
        ]


def summarize(events: list[TrafficEvent]) -> dict:
    return {
        "event_count": len(events),
        "top_sources": Counter(event.source_ip for event in events).most_common(5),
        "top_ports": Counter(event.destination_port for event in events).most_common(5),
        "unique_destinations": len({event.destination_ip for event in events}),
    }
