"""Strict loading and validation of ``audit.yml``.

The configuration can only enable/disable in-code collectors and tune limits. It can never
supply commands, and unsafe modes (non-read-only, nmap) are rejected. External validation
is opt-in: it needs ``audit.external_checks: true`` plus an explicit list of public targets,
and runs only through the separate ``external`` CLI command.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from plesk_audit.file_reader import KNOWN_LOG_FILES

PROFILES = ("baseline", "triage")
OUTPUT_FORMATS = frozenset({"json", "html"})
KNOWN_COLLECTORS = (
    "system",
    "packages",
    "services",
    "network",
    "accounts",
    "security_controls",
    "ssh",
    "plesk",
    "web_stack",
    "persistence",
    "logs",
)
MAX_CONFIG_BYTES = 64 * 1024
MAX_EXTERNAL_TARGETS = 5
_HOSTNAME_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class ConfigError(ValueError):
    """Invalid or unsafe configuration."""


@dataclass(frozen=True, slots=True)
class RuntimeConfig:
    command_timeout_seconds: float
    max_command_output_bytes: int
    max_file_bytes: int


@dataclass(frozen=True, slots=True)
class LogsConfig:
    enabled: bool
    lookback_hours: int
    max_lines_per_source: int
    sources: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ExternalConfig:
    enabled: bool
    allowed_targets: tuple[str, ...]
    tls_test_enabled: bool


@dataclass(frozen=True, slots=True)
class AuditConfig:
    profile: str
    runtime: RuntimeConfig
    output_directory: Path
    output_formats: frozenset[str]
    collectors: dict[str, bool]
    logs: LogsConfig
    external: ExternalConfig = ExternalConfig(False, (), False)


def _section(raw: dict[str, Any], key: str, allowed: set[str]) -> dict[str, Any]:
    value = raw.get(key)
    if not isinstance(value, dict):
        raise ConfigError(f"'{key}' must be a mapping")
    unknown = set(value) - allowed
    if unknown:
        raise ConfigError(f"unknown keys in '{key}': {', '.join(sorted(map(str, unknown)))}")
    return value


def _bool(section: dict[str, Any], key: str, where: str) -> bool:
    value = section.get(key)
    if not isinstance(value, bool):
        raise ConfigError(f"'{where}.{key}' must be true or false")
    return value


def _int(section: dict[str, Any], key: str, where: str, low: int, high: int) -> int:
    value = section.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ConfigError(f"'{where}.{key}' must be an integer between {low} and {high}")
    return value


def validate_target(value: object) -> str:
    """Accept a single public IP address or a fully qualified hostname; nothing broader."""
    if not isinstance(value, str) or not value or value != value.strip():
        raise ConfigError("external targets must be non-empty strings without whitespace")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        name = value.lower().rstrip(".")
        labels = name.split(".")
        if (
            len(name) > 253
            or len(labels) < 2
            or not all(_HOSTNAME_LABEL.match(label) for label in labels)
            or labels[-1].isdigit()
        ):
            raise ConfigError(
                f"external target {value!r} must be a public IP address or a fully qualified "
                "hostname (no CIDR ranges, wildcards, ports or URLs)"
            ) from None
        return name
    if not address.is_global:
        raise ConfigError(f"external target {value!r} is not a public (global) IP address")
    return str(address)


def _external(raw: dict[str, Any], enabled: bool) -> ExternalConfig:
    ext = _section(raw, "external", {"allowed_targets", "nmap_enabled", "tls_test_enabled"})
    if _bool(ext, "nmap_enabled", "external"):
        raise ConfigError("'external.nmap_enabled' must be false; nmap is never used")
    tls = _bool(ext, "tls_test_enabled", "external")
    targets = ext.get("allowed_targets")
    if not isinstance(targets, list) or len(targets) > MAX_EXTERNAL_TARGETS:
        raise ConfigError(
            f"'external.allowed_targets' must be a list of at most {MAX_EXTERNAL_TARGETS} targets"
        )
    normalized = tuple(validate_target(t) for t in targets)
    if len(set(normalized)) != len(normalized):
        raise ConfigError("'external.allowed_targets' contains duplicates")
    if enabled and not normalized:
        raise ConfigError("'audit.external_checks' requires 'external.allowed_targets'")
    if not enabled and (normalized or tls):
        raise ConfigError(
            "'external' settings require 'audit.external_checks: true' (explicit opt-in)"
        )
    return ExternalConfig(enabled, normalized, tls)


def parse_config(raw: object) -> AuditConfig:
    if not isinstance(raw, dict):
        raise ConfigError("configuration root must be a mapping")
    unknown = set(raw) - {"audit", "runtime", "output", "collectors", "logs", "external"}
    if unknown:
        raise ConfigError(f"unknown top-level keys: {', '.join(sorted(map(str, unknown)))}")

    audit = _section(raw, "audit", {"profile", "read_only", "external_checks"})
    if audit.get("profile") not in PROFILES:
        raise ConfigError(f"'audit.profile' must be one of {', '.join(PROFILES)}")
    if _bool(audit, "read_only", "audit") is not True:
        raise ConfigError("'audit.read_only' must be true; state-changing modes do not exist")
    external_enabled = _bool(audit, "external_checks", "audit")

    rt = _section(
        raw, "runtime", {"command_timeout_seconds", "max_command_output_bytes", "max_file_bytes"}
    )
    runtime = RuntimeConfig(
        command_timeout_seconds=_int(rt, "command_timeout_seconds", "runtime", 1, 120),
        max_command_output_bytes=_int(rt, "max_command_output_bytes", "runtime", 1024, 10_000_000),
        max_file_bytes=_int(rt, "max_file_bytes", "runtime", 1024, 10_000_000),
    )

    out = _section(raw, "output", {"directory", "formats", "redact_sensitive_values"})
    if not _bool(out, "redact_sensitive_values", "output"):
        raise ConfigError("'output.redact_sensitive_values' must be true")
    directory = out.get("directory")
    if not isinstance(directory, str) or not directory:
        raise ConfigError("'output.directory' must be a non-empty string")
    formats = out.get("formats")
    if (
        not isinstance(formats, list)
        or not formats
        or not all(isinstance(f, str) for f in formats)
        or not set(formats) <= OUTPUT_FORMATS
    ):
        raise ConfigError(f"'output.formats' must be a list from {sorted(OUTPUT_FORMATS)}")

    col = _section(raw, "collectors", set(KNOWN_COLLECTORS))
    collectors = {name: _bool(col, name, "collectors") for name in KNOWN_COLLECTORS if name in col}

    lg = _section(raw, "logs", {"enabled", "lookback_hours", "max_lines_per_source", "sources"})
    sources = lg.get("sources")
    if not isinstance(sources, list) or not all(
        isinstance(s, str) and s in KNOWN_LOG_FILES for s in sources
    ):
        raise ConfigError(f"'logs.sources' must be a list from {sorted(KNOWN_LOG_FILES)}")
    logs = LogsConfig(
        enabled=_bool(lg, "enabled", "logs"),
        lookback_hours=_int(lg, "lookback_hours", "logs", 1, 24 * 90),
        max_lines_per_source=_int(lg, "max_lines_per_source", "logs", 1, 100_000),
        sources=tuple(sources),
    )

    external = _external(raw, external_enabled)

    return AuditConfig(
        profile=audit["profile"],
        runtime=runtime,
        output_directory=Path(directory),
        output_formats=frozenset(formats),
        collectors=collectors,
        logs=logs,
        external=external,
    )


def load_config(path: Path) -> AuditConfig:
    try:
        size = path.stat().st_size
        if size > MAX_CONFIG_BYTES:
            raise ConfigError(f"configuration file exceeds {MAX_CONFIG_BYTES} bytes")
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read configuration: {type(exc).__name__}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML: {exc}") from exc
    return parse_config(raw)
