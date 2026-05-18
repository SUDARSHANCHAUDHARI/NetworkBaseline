"""Build a simple normal-traffic baseline."""

from __future__ import annotations

from dataclasses import dataclass

from src.traffic_summary import TrafficEvent


@dataclass(frozen=True)
class Baseline:
    allowed_ports: set[int]
    known_sources: set[str]
    known_destinations: set[str]
    known_protocols: set[str]
    max_events_per_source: int


def build_baseline(events: list[TrafficEvent]) -> Baseline:
    counts: dict[str, int] = {}
    for event in events:
        counts[event.source_ip] = counts.get(event.source_ip, 0) + 1
    max_events = max(counts.values(), default=0)
    return Baseline(
        allowed_ports={event.destination_port for event in events},
        known_sources={event.source_ip for event in events},
        known_destinations={event.destination_ip for event in events},
        known_protocols={event.protocol for event in events},
        max_events_per_source=max_events,
    )
