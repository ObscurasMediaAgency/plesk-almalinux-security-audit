
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

## VM validation checklist (roadmap phase 8)
Run on a disposable AlmaLinux 9.9 + Plesk Obsidian 18.0.82.31 VM before any production run. Take a snapshot first; the VM must contain no customer data. Compare each parser against the raw output shown by the commands below (run them manually as root on the VM). If a format differs, adjust the parser and add a **synthetic** fixture that reproduces the format — never copy real output, hostnames, IPs or usernames into `tests/fixtures/`. Remove the corresponding `VERIFY` marker only after the check passed.

| # | Item | Manual reference command | Check | Code / docs |
|---|---|---|---|---|
| 1 | Plesk version file | `cat /usr/local/psa/version` | path exists; format `18.0.82 <OS> <build>` | `collectors/system.py`, `file_reader.py` |
| 2 | Plesk CLI version | `plesk version` | `Key: value` lines incl. product version | `collectors/plesk.py`, `safe_exec.py` |
| 3 | Plesk extensions | `plesk bin extension --list` | `id - name - version` lines; no state change | `collectors/plesk.py` |
| 4 | Security updates | `dnf -q -C updateinfo list --security --available` | `<advisory> <Severity>/Sec. <nevra>`; behaviour with empty/expired cache | `collectors/packages.py`, `safe_exec.py` |
| 5 | Effective sshd config | `sshd -T` | runs as root without side effects; `permitrootlogin` spelling (`without-password` vs. `prohibit-password`) | `collectors/ssh.py` |
| 6 | firewalld state | `firewall-cmd --state; echo $?` | exit code 252 when stopped | `collectors/security_controls.py` |
| 7 | firewalld zones | `firewall-cmd --list-all-zones` | header `public (default, active)` / `(active)`, two-space indentation, rich rules | `collectors/security_controls.py` |
| 8 | Plesk Firewall | Plesk UI → Firewall, then #7 | Plesk Firewall rules appear in firewalld output (otherwise NET-001 is unreliable) | `STATIC_LIMITATIONS` in `runner.py` |
| 9 | Fail2Ban | `fail2ban-client status` | `Jail list:` line format in fail2ban 1.x; Plesk jail names containing `ssh` | `collectors/security_controls.py` |
| 10 | rsyslog timestamps | `tail -n 3 /var/log/secure /var/log/maillog` | classic `Mon dd HH:MM:SS` vs. RFC 3339; host timezone | `collectors/logs.py` |
| 11 | sshd/sudo messages | generate a failed, an invalid-user and a successful SSH login plus one `sudo` call on the VM | LOG-001…003 counters match; no message bodies or commands in `evidence.json` | `collectors/logs.py` |
| 12 | Mail auth messages | one failed SMTP AUTH (Postfix) and one failed IMAP login (Dovecot) on the VM | LOG-004 counters match | `collectors/logs.py` |
| 13 | Persistence metadata | `ls -la /etc/cron.d /var/spool/cron /etc/systemd/system /etc/profile.d` | entry counts/owners match `EV-persistence-*`; Plesk-owned entries understood (PER-003 false positives?) | `collectors/persistence.py` |
| 14 | Non-root run | run `collect` as an unprivileged user | collectors degrade to `partial`/`error` with clear messages, no crash | all collectors |
| 15 | External validation | from a second host: `plesk-audit external --confirm-authorized` against the VM | open ports and TLS results match the VM's firewalld config; EXT-* plausible; certificate of Plesk panel (8443) | `external.py` |

Additional checks:
- Runtime: a full `collect --profile triage` finishes within a few minutes and does not cause noticeable load (watch `top` during the run).
- No state change: compare `rpm -Va`, `systemctl list-units --failed`, `firewall-cmd --list-all-zones` and `ls -la /var/log` before and after the run; nothing may differ except log lines caused by the audit itself (e.g. `sudo` entries).
- Reports: directory mode `0700`, files `0600`; `grep` the reports for secrets/hashes (`\$6\$`, `BEGIN .*PRIVATE KEY`) — there must be no hits.
- Record the result (date, tool commit, VM image, passed items, deviations) outside the repository; open an issue for each deviation.
