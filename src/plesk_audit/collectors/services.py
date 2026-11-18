"""systemd service and timer inventory.

Privileges: none. Data: unit name, type, load/active/sub state, unit-file state.
Descriptions are not collected.
"""

from __future__ import annotations

from typing import Any

from plesk_audit.collectors.base import Collection, CollectorContext
from plesk_audit.models import CollectorResult

NAME = "services"
_UNIT_TYPES = ("service", "timer")


def _unit_type(unit: str) -> str:
    kind = unit.rpartition(".")[2]
    if kind not in _UNIT_TYPES:
        raise ValueError("unexpected unit type")
    return kind


def parse_list_units(text: str) -> dict[str, dict[str, str]]:
    units: dict[str, dict[str, str]] = {}
    for line in text.splitlines():
        parts = line.removeprefix("●").split()
        if not parts:
            continue
        if len(parts) < 4:
            raise ValueError("unexpected list-units output")
        unit, load, active, sub = parts[:4]
        units[unit] = {"type": _unit_type(unit), "load": load, "active": active, "sub": sub}
    return units


def parse_unit_files(text: str) -> dict[str, str]:
    states: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        if len(parts) < 2:
            raise ValueError("unexpected list-unit-files output")
        _unit_type(parts[0])
        states[parts[0]] = parts[1]
    return states


def merge_units(loaded: dict[str, dict[str, str]], files: dict[str, str]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    for unit in sorted(set(loaded) | set(files)):
        state = loaded.get(
            unit,
            {"type": _unit_type(unit), "load": "not-loaded", "active": "inactive", "sub": "dead"},
        )
        merged.append({"unit": unit, **state, "unit_file_state": files.get(unit)})
    return merged


def collect(ctx: CollectorContext) -> CollectorResult:
    c = Collection(NAME, ctx)
    loaded: dict[str, dict[str, str]] | None = None
    files: dict[str, str] | None = None

    units_cmd = c.command("systemctl_units")
    if units_cmd is not None:
        loaded = c.parse("systemctl_units", parse_list_units, units_cmd.stdout)
    files_cmd = c.command("systemctl_unit_files")
    if files_cmd is not None:
        files = c.parse("systemctl_unit_files", parse_unit_files, files_cmd.stdout)

    if loaded is not None or files is not None:
        units = merge_units(loaded or {}, files or {})
        c.add(
            "units",
            "command:systemctl list-units/list-unit-files",
            {
                "units": units,
                "failed": [u["unit"] for u in units if u["active"] == "failed"],
                "enabled_count": sum(1 for u in units if u["unit_file_state"] == "enabled"),
            },
        )
    return c.result()
