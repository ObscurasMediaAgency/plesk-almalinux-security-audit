
# Scope, Authorization and Safety

## Authorized target
Initial target: AlmaLinux 9.9 x86_64, Plesk Obsidian 18.0.82.31, dedicated root server. The operator must confirm ownership or explicit authorization before each run.

## Modes
- **Local baseline (default):** local read-only inventory; no outbound network traffic.
- **Compromise triage:** deeper bounded review of selected logs, accounts, services, processes, timers and persistence metadata.
- **External validation (opt-in):** only explicitly approved public IPs/hostnames in an allow-list, with a written scope and rate limits.

## External validation controls
- Runs only via `plesk-audit external --confirm-authorized`; `collect` never sends outbound traffic.
- Requires `audit.external_checks: true` and 1–5 explicit targets (public IP or fully qualified hostname). CIDR ranges, wildcards, URLs, ports and private, loopback or documentation addresses are rejected; resolved non-public addresses are skipped.
- Only TCP connects to a fixed in-code port list and TLS handshakes (including TLS 1.0/1.1 acceptance) are performed, sequentially, with a 0.5 s pause and at most 5 s timeout per probe. No payloads, logins, banner grabbing, vulnerability tests or nmap.
- Inform the hosting provider/SOC if intrusion detection may alert, and run from a documented source address. Results depend on that source address.

## Data minimization
Never collect password hashes, private keys, API keys, tokens, database table contents, mailbox contents or customer application secrets. Redact hostnames/IPs/usernames if reports are to be shared externally; preserve identifiers only where operationally necessary and securely stored.

## Production precautions
Confirm a recoverable backup/snapshot and maintenance constraints. Start with non-invasive inventory. Avoid heavy filesystem scans during peak traffic. Do not install packages on production solely for the audit. Preserve original logs. If compromise is suspected, do not clean up or reboot before evidence-preservation decisions.

## Limitations
A clean audit does not prove a host is uncompromised. Log rotation, disabled auditing, tampering, root-level attacker access and incomplete telemetry can conceal activity. Human validation is required.
