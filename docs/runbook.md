
# Operator Runbook

Before running: confirm authorization, exact target, backup/snapshot, maintenance constraints, enabled collectors and restricted report storage.

Start with a local baseline, no external checks and no log triage. Review collector errors and limitations. Enable bounded log triage only after reviewing source paths and retention windows: set `collectors.logs: true` and `logs.enabled: true`, then run with `--profile triage` (persistence metadata is also collected only in this profile). Preserve original logs. Validate high-severity findings manually and compare against a known-good baseline. Never commit production reports to source control.

## Running
```bash
plesk-audit collect --config config/audit.yml --output /root/audit-reports --verbose
```
Run as root for complete process attribution; without root the `network` collector reports `partial`. Choose an output directory outside web roots and backups that are shared. Check `manifest.json` for `partial`/`error`/`skipped` collectors and the `limitations` list before interpreting findings.

## External validation (opt-in)
Only after written authorization for every target: set `audit.external_checks: true`, list the targets in `external.allowed_targets` (public IPs or FQDNs, max. 5) and optionally `tls_test_enabled: true`. Review the scope, then run from a documented, external source address:
```bash
plesk-audit external --config /root/audit-external.yml --confirm-authorized --output /root/audit-reports
```
Keep this configuration separate from the local baseline configuration. Repeat from a second network if firewall allow-lists depend on the source address.
