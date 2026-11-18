from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest
import yaml

from plesk_audit.config import ConfigError, load_config, parse_config

REPO_CONFIG = Path(__file__).parents[1] / "config" / "audit.yml"


def base() -> dict[str, Any]:
    raw = yaml.safe_load(REPO_CONFIG.read_text(encoding="utf-8"))
    assert isinstance(raw, dict)
    return raw


def test_repository_config_is_valid() -> None:
    config = load_config(REPO_CONFIG)
    assert config.profile == "baseline"
    assert config.collectors["system"] is True
    assert config.output_formats == {"json", "html"}


@pytest.mark.parametrize(
    ("section", "key", "value"),
    [
        ("audit", "read_only", False),
        ("audit", "external_checks", True),
        ("audit", "profile", "external"),
        ("output", "redact_sensitive_values", False),
        ("output", "formats", ["pdf"]),
        ("runtime", "command_timeout_seconds", 0),
        ("runtime", "max_file_bytes", True),
        ("logs", "sources", ["/etc/shadow"]),
        ("logs", "sources", ["/var/log/../../etc/shadow"]),
        ("external", "allowed_targets", ["192.0.2.1"]),
        ("external", "nmap_enabled", True),
        ("collectors", "unknown_collector", True),
        ("audit", "command", "rm -rf /"),
    ],
)
def test_rejects_unsafe_or_invalid_values(section: str, key: str, value: object) -> None:
    raw = copy.deepcopy(base())
    raw[section][key] = value
    with pytest.raises(ConfigError):
        parse_config(raw)


def test_rejects_unknown_top_level_key() -> None:
    raw = base() | {"commands": ["id"]}
    with pytest.raises(ConfigError):
        parse_config(raw)


def test_rejects_oversized_file(tmp_path: Path) -> None:
    path = tmp_path / "big.yml"
    path.write_text("#" * (70 * 1024))
    with pytest.raises(ConfigError):
        load_config(path)
