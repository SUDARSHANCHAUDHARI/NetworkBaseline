from pathlib import Path
import unittest

from src.anomaly_detector import build_report, build_source_risk, build_summary, build_triage_report, detect_anomalies
from src.baseline_builder import build_baseline
from src.traffic_summary import parse_traffic, summarize


ROOT = Path(__file__).resolve().parents[1]


class NetworkBaselineTests(unittest.TestCase):
    def test_detects_new_source_and_ports(self) -> None:
        normal = parse_traffic(ROOT / "data/normal.csv")
        observed = parse_traffic(ROOT / "data/attack.csv")
        anomalies = detect_anomalies(observed, build_baseline(normal))

        self.assertTrue(any(item.reason == "new source IP not seen in baseline" for item in anomalies))
        self.assertTrue(any(item.destination_port == 4444 for item in anomalies))
        self.assertTrue(any(item.kind == "baseline.volume_spike" for item in anomalies))

    def test_summary_counts_events(self) -> None:
        self.assertEqual(4, summarize(parse_traffic(ROOT / "data/normal.csv"))["event_count"])

    def test_report_is_markdown(self) -> None:
        report = build_report([], [], [])
        self.assertIn("Network Baseline Report", report)

    def test_builds_source_risk_and_triage(self) -> None:
        normal = parse_traffic(ROOT / "data/normal.csv")
        observed = parse_traffic(ROOT / "data/attack.csv")
        anomalies = detect_anomalies(observed, build_baseline(normal))
        summary = build_summary(normal, observed, anomalies)
        source_risk = build_source_risk(observed, anomalies)
        triage = build_triage_report(summary, source_risk, anomalies)

        self.assertEqual(5, summary["observed_events"])
        self.assertTrue(any(row["source_ip"] == "198.51.100.80" and row["max_severity"] == "high" for row in source_risk))
        self.assertIn("Network Baseline Triage", triage)


if __name__ == "__main__":
    unittest.main()
