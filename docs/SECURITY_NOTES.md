# Security Notes

This project is defensive and analysis-only. Use it only with network logs from systems and networks you own or have permission to monitor.

## Data Handling

- Network logs can expose internal IPs, destinations, ports, protocols, and timing.
- Redact private host mappings and sensitive destinations before sharing reports.
- Do not commit production network telemetry.
- Sample data uses documentation IP ranges and synthetic internal addresses.

## Detection Caveats

- Baseline drift is not automatically malicious.
- Deployments, new services, scans, and scheduled jobs can create legitimate drift.
- Confirm findings with asset inventory, firewall policy, DNS, and endpoint telemetry.
