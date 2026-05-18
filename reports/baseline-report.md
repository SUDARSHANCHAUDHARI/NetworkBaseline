# Network Baseline Report

- Normal events: 4
- Observed events: 5
- Anomalies: 8
- High severity: 4
- Medium severity: 4
- Observed unique destinations: 1

## Source Risk

- `198.51.100.80`: high, anomalies=8, types=baseline.new_port, baseline.new_source, baseline.volume_spike
- `10.0.0.10`: low, anomalies=0, types=none

## Anomalies

### 198.51.100.80 -> 10.0.0.20:4444

- Severity: `medium`
- Type: `baseline.new_source`
- Reason: new source IP not seen in baseline
- Recommended next step: Confirm whether this source is expected, then add to baseline or investigate the host.

### 198.51.100.80 -> 10.0.0.20:4444

- Severity: `high`
- Type: `baseline.new_port`
- Reason: destination port not seen in baseline
- Recommended next step: Review the destination service and verify whether this port should be allowed.

### 198.51.100.80 -> 10.0.0.20:8080

- Severity: `medium`
- Type: `baseline.new_source`
- Reason: new source IP not seen in baseline
- Recommended next step: Confirm whether this source is expected, then add to baseline or investigate the host.

### 198.51.100.80 -> 10.0.0.20:8080

- Severity: `high`
- Type: `baseline.new_port`
- Reason: destination port not seen in baseline
- Recommended next step: Review the destination service and verify whether this port should be allowed.

### 198.51.100.80 -> 10.0.0.20:3389

- Severity: `medium`
- Type: `baseline.new_source`
- Reason: new source IP not seen in baseline
- Recommended next step: Confirm whether this source is expected, then add to baseline or investigate the host.

### 198.51.100.80 -> 10.0.0.20:3389

- Severity: `high`
- Type: `baseline.new_port`
- Reason: destination port not seen in baseline
- Recommended next step: Review the destination service and verify whether this port should be allowed.

### 198.51.100.80 -> 10.0.0.20:22

- Severity: `medium`
- Type: `baseline.new_source`
- Reason: new source IP not seen in baseline
- Recommended next step: Confirm whether this source is expected, then add to baseline or investigate the host.

### 198.51.100.80 -> *:0

- Severity: `high`
- Type: `baseline.volume_spike`
- Reason: connection volume 4 exceeds baseline
- Recommended next step: Check whether this is an authorized batch job, scan, or compromised host.
