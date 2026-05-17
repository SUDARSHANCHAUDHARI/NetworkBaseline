from pathlib import Path
import unittest

from src.anomaly_detector import build_report, detect_anomalies
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

    def test_summary_counts_events(self) -> None:
        self.assertEqual(4, summarize(parse_traffic(ROOT / "data/normal.csv"))["event_count"])

    def test_report_is_markdown(self) -> None:
        report = build_report([], [], [])
        self.assertIn("Network Baseline Report", report)


if __name__ == "__main__":
    unittest.main()
