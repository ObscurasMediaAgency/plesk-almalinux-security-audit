
# Report Schema

Top-level JSON fields:
- `schema_version`
- `run`: run ID, tool version, timestamps, hostname, OS and Plesk version
- `collectors`: status and reason for each collector
- `evidence`: normalized records with source, timestamp and redaction status
- `findings`: findings following the contract in `AGENT.md`
- `limitations`: gaps and incomplete coverage

These fields are split across files in a per-run directory `run-<UTC timestamp>-<run id prefix>/`:
- `manifest.json`: `schema_version`, `run`, `collectors` (`name`, `status`, `message`, `evidence_ids`), `limitations`
- `evidence.json`: `schema_version`, `run_id`, `evidence` (`evidence_id`, `collector`, `source`, `collected_at`, `data`, `redacted`), sorted by ID
- `findings.json`: `schema_version`, `run_id`, `findings`, sorted by ID
- `report.html`: human-readable rendering of the above

Current `schema_version`: `1.0`. Timestamps are UTC in `YYYY-MM-DDTHH:MM:SSZ`. JSON keys are sorted for deterministic output.

Raw evidence must be separated from interpreted findings. Secrets must never be serialized.
