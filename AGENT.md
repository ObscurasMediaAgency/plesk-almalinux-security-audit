
# Agent Instructions

## Mission
Build a defensive, evidence-oriented, read-only security audit toolkit for an authorized AlmaLinux 9.9 x86_64 dedicated server running Plesk Obsidian 18.0.82.31.

Support both security posture assessment and compromise triage. An indicator is not proof of compromise. Distinguish observations, hypotheses and confirmed findings.

## Mandatory safety constraints
- Default behavior is read-only.
- Never implement remediation, hardening, deletion, quarantine, service restart, package update, firewall modification, account modification or permission modification.
- No exploitation, privilege escalation, persistence, password cracking, evasion or payload execution.
- Never read/export password hashes, private keys, API tokens, passwords, database contents, mailbox contents or application secrets.
- No broad filesystem crawls by default. Use explicit bounded paths and file-size limits.
- No external network connections unless explicitly enabled with an approved target allow-list.
- Do not scan third-party targets.
- Redact sensitive values before persistence, logging or reporting.
- Never use `shell=True`, `os.system`, dynamic shell strings or arbitrary commands from YAML.
- Use subprocess argument arrays, strict in-code command allow-lists, timeouts and output limits.
- Treat command output, filenames, logs and configuration as untrusted input.
- Do not add state-changing features. If a future request proposes one, stop and request explicit human review.

## Engineering standards
- Python 3.11+, standard library wherever practical.
- Type hints, small modules and dataclasses/typed models.
- Deterministic output; UTC timestamps in machine-readable output.
- Structured logging; do not log raw potentially sensitive command output.
- Gracefully handle missing commands, permissions and unsupported components.
- Collector statuses: `ok`, `partial`, `skipped`, `error`, with a reason.
- Unit tests use fixtures/mocks; never require root or a live server.
- Keep dependencies minimal and justify additions.

## Required finding fields
`id`, `title`, `domain`, `severity`, `confidence`, `status`, `summary`, `evidence_refs`, `impact`, `recommendation`, `detected_at`, optional `references`.

Severity: `critical`, `high`, `medium`, `low`, `info`.
Confidence: `high`, `medium`, `low`.
Status: `observed`, `needs_review`, `confirmed`, `not_applicable`.

Do not elevate severity solely because a scanner labels an issue critical. Explain exposure and context.

## Collector pattern
1. Define evidence fields and source.
2. Implement one narrow collector.
3. Use safe command runner or bounded file reader.
4. Normalize and redact immediately.
5. Add deterministic fixture-based tests.
6. Keep finding rules separate from collection logic.
7. Document privileges, limitations and data collected.

Never silently skip errors.

## Plesk guidance
- Verify paths, commands and CLI options against the installed Plesk build; do not guess.
- Prefer documented Plesk read-only CLI commands.
- Inventory version/components before version-specific checks.
- Treat Plesk-managed configuration as generated; never edit it.
- Do not assume firewalld and Plesk Firewall are interchangeable.
- Never disable/reconfigure Plesk services.

## Compromise triage
Initially collect bounded metadata only: UID 0 accounts, unexpected local accounts, processes/executable paths, listening sockets, enabled services/timers, cron metadata, recent authentication events, selected Plesk/web/mail/firewall log patterns and scoped SUID/SGID metadata.

Do not label a file/process malicious based on its name alone. Record timestamps, source and confidence.

## Reporting
Separate evidence from interpretation. Include run ID, tool version, OS/Plesk identification, timestamps, failed collectors and limitations. Escape all host-derived HTML text. No active scripts or remote assets in reports.

## Definition of done
A feature is complete only when it meets safety constraints, has tests, documents privileges/data, handles errors, avoids secrets and produces deterministic output.
