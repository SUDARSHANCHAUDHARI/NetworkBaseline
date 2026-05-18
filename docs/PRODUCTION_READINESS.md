# Production Readiness

## Current Status

This repository has a working local MVP with deterministic traffic parsing, safe sample data, generated reports, and tests. It is not production complete yet.

## Required Before Public Release

- Add rolling baseline windows and baseline approval history.
- Validate CSV schema and report parse errors without stopping whole-file analysis.
- Add structured logging without leaking secrets.
- Add allowlist/suppression workflow for expected drift.
- Add authentication and authorization before storing multi-user logs.
- Add retention controls for uploaded traffic logs and generated reports.
- Run dependency and secret scans before release.

## Definition of Done

- CI passes on pull requests.
- README has setup, usage, and security notes.
- Sample data is safe to publish.
- Error paths are handled clearly.
- No secrets or local machine paths are committed.
