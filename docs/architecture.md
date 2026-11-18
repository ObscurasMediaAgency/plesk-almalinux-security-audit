
# Architecture

Pipeline: CLI -> configuration validation -> collector runner -> normalized evidence -> redaction -> rule evaluation -> JSON/HTML reporters.

- `config.py` loads `audit.yml` with `yaml.safe_load` and validates it strictly (unknown keys, unsafe modes and out-of-range limits are rejected).
- `safe_exec.py` runs commands by symbolic name from the in-code `ALLOWED_COMMANDS` map: fixed argv, no shell, minimal environment (`PATH`, `LC_ALL=C`), timeout with process-group kill, bounded stdout/stderr, immediate redaction.
- `file_reader.py` reads only paths in `ALLOWED_FILES`; the resolved symlink target must also be allow-listed, only regular files are read, size is capped, content is redacted.
- `collectors/` gather facts only; no severity decisions. Each collector is a function `collect(ctx) -> CollectorResult`, registered in `collectors/__init__.py`. Parsers are pure functions for fixture testing.
- `rules/` evaluate evidence and create findings. A failing rule becomes a limitation instead of aborting the run.
- `models.py` defines typed evidence/finding/status/run structures.
- `runner.py` selects collectors, isolates collector exceptions, evaluates rules and writes reports into a new `0700` run directory (files `0600`, never overwritten).
- `redaction.py` handles sensitive-value removal (key/value secrets, auth headers, private key blocks).
- `reporters/` serialize output; JSON is sorted and timestamps are UTC (`...Z`). HTML escapes all host-derived text, sets a restrictive CSP and loads no scripts or remote assets.

Disabled or not-yet-implemented collectors are reported as `skipped` with a reason; they are never silently omitted. See `collectors.md` for per-collector privileges and data.

Profiles: `baseline` (local inventory), `triage` (baseline plus bounded log/persistence metadata), `external` (separate opt-in workflow; never default).

Commands must be fixed in code, invoked as argument arrays, and never sourced from YAML. File readers need explicit paths and size caps.
