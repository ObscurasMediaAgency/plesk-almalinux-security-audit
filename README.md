
# Plesk / AlmaLinux Security Audit Toolkit

Defensive, read-only audit toolkit for an authorized AlmaLinux 9.9 x86_64 dedicated server running Plesk Obsidian 18.0.82.31.

## Objectives
- Assess security posture and configuration weaknesses.
- Inventory exposed services, packages, users, scheduled tasks and security controls.
- Perform bounded, privacy-conscious compromise triage.
- Produce normalized JSON evidence, findings and an HTML report.

## Safety
The default mode is local and read-only. No remediation, exploitation, password cracking, persistence, package updates, service changes, firewall changes or account changes are implemented. External checks are disabled by default and require an explicit target allow-list and separate authorization. Never collect password hashes, private keys, API tokens, database contents, mailbox contents or application secrets.

## Structure
```text
.
├── AGENT.md
├── README.md
├── pyproject.toml
├── config/audit.yml
├── docs/
├── src/plesk_audit/
│   ├── cli.py
│   ├── config.py        # strict audit.yml validation
│   ├── runner.py
│   ├── models.py
│   ├── safe_exec.py     # allow-listed command runner
│   ├── file_reader.py   # allow-listed bounded file reader
│   ├── redaction.py
│   ├── collectors/
│   ├── rules/
│   └── reporters/
└── tests/               # fixture-based, no root or live server
```

## Development setup
Python 3.11+ is recommended.
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
pytest
ruff check src tests
mypy src tests
```

## Usage
```bash
plesk-audit collect --config config/audit.yml [--output /secure/reports] [--profile baseline|triage] [--verbose]
```
Reports are written to a new `run-<timestamp>-<id>/` directory (mode `0700`, files `0600`); existing runs are never overwritten. Exit codes: `0` success, `1` output error, `2` configuration error.

## Status
Implemented: safe command runner, bounded file reader, strict config validation, `system` and `network` collectors, first finding rules, JSON and HTML reporting. All other collectors report `skipped` (`not implemented yet`). See `docs/collectors.md` for sources, privileges and data. Validate on a test VM before running on production.

## Planned audit domains
1. Host baseline: OS, kernel, uptime, time synchronization.
2. Patch posture: installed packages and available security updates (without applying updates).
3. Network: local listening sockets, firewalld state and zones.
4. Services: running/enabled services, failed units and timers.
5. Identity: local accounts, UID 0 accounts, sudo policy metadata and SSH key metadata.
6. SSH: effective daemon configuration and authentication policy.
7. Plesk: installed build, components and verified read-only settings.
8. Web stack: Apache, Nginx, PHP and TLS posture.
9. Databases: service/listener and access-policy metadata; no database contents.
10. Security controls: SELinux, firewalld, Fail2Ban, auditd, AIDE and ClamAV.
11. Compromise triage: bounded log review, unexpected processes/listeners and persistence metadata.
12. Reporting: findings, evidence, limitations and prioritized recommendations.

## First operational approach
Start with a reviewed local baseline on a test VM. On production, confirm authorization, backup/snapshot, maintenance constraints and secure report storage. Do not install packages on production merely to run the toolkit.

## Output contract
- `manifest.json`: run metadata and collector status.
- `evidence.json`: normalized, redacted evidence.
- `findings.json`: machine-readable findings.
- `report.html`: human-readable report.

Do not commit real production reports. Reports may contain hostnames, IP addresses, usernames and security-relevant configuration.

## Roadmap
1. ~~Safe command runner, timeout/output limits and redaction.~~ Done.
2. Host, package, service and network collectors. (Host and network done.)
3. SSH, SELinux, firewalld and Fail2Ban checks.
4. Plesk-specific read-only inventory for the installed build.
5. Bounded log triage and compromise indicators.
6. JSON/HTML reporting and tests. (Initial version done.)
7. Explicitly opt-in external validation.
8. Validation on a disposable AlmaLinux 9.9 + Plesk VM.

Internal project scaffold; add an explicit license before distribution.
