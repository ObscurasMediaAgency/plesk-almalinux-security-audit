"""SELinux, firewalld and Fail2Ban state.

Privileges: none for SELinux and the firewalld state; root for firewalld zone details
(polkit) and the Fail2Ban socket, otherwise ``partial``. Data: SELinux runtime/config
mode; firewalld state, default zone and per-zone target, interfaces, sources, services,
ports and rich rules; Fail2Ban jail names. Banned IP lists are not collected.
Plesk Firewall rules are only visible insofar as they are applied through firewalld;
direct nftables/iptables rules are not evaluated.
"""

from __future__ import annotations

from typing import Any

from plesk_audit.collectors.base import Collection, CollectorContext
from plesk_audit.models import CollectorResult

NAME = "security_controls"
FIREWALLD_NOT_RUNNING = 252
_ZONE_LIST_FIELDS = ("interfaces", "sources", "services", "ports", "protocols", "source-ports")


def parse_selinux_config(text: str) -> dict[str, str | None]:
    values: dict[str, str | None] = {"SELINUX": None, "SELINUXTYPE": None}
    for line in text.splitlines():
        key, sep, value = line.strip().partition("=")
        if sep and key in values:
            values[key] = value.strip().strip("\"'").lower()
    return {"config_mode": values["SELINUX"], "config_type": values["SELINUXTYPE"]}


def parse_zones(text: str) -> list[dict[str, Any]]:
    """Parse ``firewall-cmd --list-all-zones`` blocks."""
    zones: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    field: str | None = None
    for raw in text.splitlines():
        if not raw.strip():
            continue
        if not raw[0].isspace():
            name, _, flags = raw.strip().partition(" ")
            flag_set = {f.strip() for f in flags.strip("()").split(",") if f.strip()}
            current = {
                "name": name,
                "active": "active" in flag_set,
                "default": "default" in flag_set,
                "target": None,
                "rich_rules": [],
                **{f: [] for f in _ZONE_LIST_FIELDS},
            }
            zones.append(current)
            field = None
            continue
        if current is None:
            raise ValueError("zone property before zone header")
        line = raw.strip()
        key, sep, value = line.partition(":")
        if sep and key in (*_ZONE_LIST_FIELDS, "target", "rich rules"):
            field = key
            if key == "target":
                current["target"] = value.strip()
            elif key in _ZONE_LIST_FIELDS:
                current[key] = value.split()
            continue
        if field == "rich rules" and line.startswith("rule "):
            current["rich_rules"].append(line)
            continue
        field = None
    if not zones:
        raise ValueError("no zones")
    return zones


def parse_fail2ban_status(text: str) -> list[str]:
    for line in text.splitlines():
        _, sep, value = line.partition("Jail list:")
        if sep:
            return sorted(j.strip() for j in value.split(",") if j.strip())
    raise ValueError("no jail list")


def _selinux(c: Collection) -> None:
    data: dict[str, Any] = {}
    getenforce = c.command("getenforce")
    if getenforce is not None:
        data["runtime_mode"] = getenforce.stdout.strip().lower() or None
    config = c.file("/etc/selinux/config", missing_ok=True)
    if config is not None:
        data.update(parse_selinux_config(config.content))
    if data:
        c.add("selinux", "command:getenforce, file:/etc/selinux/config", data)


def _firewalld(c: Collection) -> None:
    state = c.command("firewalld_state", ok_codes=(0, FIREWALLD_NOT_RUNNING))
    if state is None:
        return
    running = state.returncode == 0 and state.stdout.strip() == "running"
    data: dict[str, Any] = {"running": running, "default_zone": None, "zones": None}
    if running:
        default = c.command("firewalld_default_zone")
        if default is not None:
            data["default_zone"] = default.stdout.strip() or None
        zones_cmd = c.command("firewalld_zones")
        if zones_cmd is not None:
            data["zones"] = c.parse("firewalld_zones", parse_zones, zones_cmd.stdout)
        if data["zones"] and data["default_zone"]:
            for zone in data["zones"]:
                zone["default"] = zone["default"] or zone["name"] == data["default_zone"]
    c.add("firewalld", "command:firewall-cmd", data)


def _fail2ban(c: Collection) -> None:
    raw = c.ctx.commands.run("fail2ban_status")
    if raw.status == "missing":
        c.add("fail2ban", "command:fail2ban-client status", {"installed": False, "jails": None})
        return
    status = c.check(raw)
    if status is not None:
        jails = c.parse("fail2ban_status", parse_fail2ban_status, status.stdout)
        if jails is not None:
            c.add("fail2ban", "command:fail2ban-client status", {"installed": True, "jails": jails})


def collect(ctx: CollectorContext) -> CollectorResult:
    c = Collection(NAME, ctx)
    _selinux(c)
    _firewalld(c)
    _fail2ban(c)
    return c.result()
