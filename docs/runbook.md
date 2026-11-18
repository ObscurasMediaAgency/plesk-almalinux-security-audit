
# Operator Runbook

Before running: confirm authorization, exact target, backup/snapshot, maintenance constraints, enabled collectors and restricted report storage.

Start with a local baseline, no external checks and no log triage. Review collector errors and limitations. Enable bounded log triage only after reviewing source paths and retention windows. Preserve original logs. Validate high-severity findings manually and compare against a known-good baseline. Never commit production reports to source control.

## Running
```bash
plesk-audit collect --config config/audit.yml --output /root/audit-reports --verbose
```
Run as root for complete process attribution; without root the `network` collector reports `partial`. Choose an output directory outside web roots and backups that are shared. Check `manifest.json` for `partial`/`error`/`skipped` collectors and the `limitations` list before interpreting findings.
