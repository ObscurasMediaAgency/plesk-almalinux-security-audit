
Read `AGENT.md` and `docs/scope-and-safety.md` before changing code.

This is a defensive, read-only audit tool for an authorized AlmaLinux 9.9 / Plesk Obsidian 18.0.82.31 server. No remediation, exploitation, credential access, uncontrolled scans or external connections by default.

Use Python 3.11+, type hints, minimal dependencies, subprocess argument arrays (never `shell=True`), strict allow-lists, timeouts, output limits and immediate redaction. Add fixture-based tests for every collector and finding rule. Never put real server data or secrets into fixtures.

If a command, path or Plesk CLI option is uncertain, mark it for verification against the installed build rather than guessing.
