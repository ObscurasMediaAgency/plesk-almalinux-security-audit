"""Local listening sockets via ``ss``.

Privileges: process names/PIDs are only visible as root; without root the collector
reports ``partial``. Data: protocol, local address/port, bind scope, process names/PIDs.
No traffic is generated and no remote endpoints are contacted.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Literal

from plesk_audit.collectors.base import CollectorContext
from plesk_audit.models import CollectorResult, CollectorStatus, Evidence

NAME = "network"
BindScope = Literal["wildcard", "loopback", "specific"]
_PROC_RE = re.compile(r'\("((?:[^"\\]|\\.)*)",pid=(\d+)')
_WILDCARDS = frozenset({"*", "0.0.0.0", "::"})


def classify_address(address: str) -> BindScope:
    if address in _WILDCARDS:
        return "wildcard"
    try:
        return "loopback" if ipaddress.ip_address(address).is_loopback else "specific"
    except ValueError:
        return "specific"


def split_local(local: str) -> tuple[str, str | None, int]:
    """Split ``addr[%iface]:port``; IPv6 addresses appear as ``[addr]``."""
    host, sep, port = local.rpartition(":")
    if not sep or not port.isdigit():
        raise ValueError("unparsable local address")
    address, _, interface = host.partition("%")
    address = address.removeprefix("[").removesuffix("]")
    if not address:
        raise ValueError("empty address")
    return address, interface or None, int(port)


def parse_ss_line(line: str) -> dict[str, Any]:
    parts = line.split(None, 6)
    if len(parts) < 6:
        raise ValueError("too few columns")
    netid, state, _recv_q, _send_q, local, _peer = parts[:6]
    if netid not in ("tcp", "udp"):
        raise ValueError("unexpected protocol")
    address, interface, port = split_local(local)
    processes = _PROC_RE.findall(parts[6]) if len(parts) == 7 else []
    return {
        "protocol": netid,
        "state": state,
        "address": address,
        "interface": interface,
        "port": port,
        "bind_scope": classify_address(address),
        "processes": sorted({name for name, _ in processes}),
        "pids": sorted({int(pid) for _, pid in processes}),
    }


def parse_ss(text: str) -> tuple[list[dict[str, Any]], int]:
    listeners: list[dict[str, Any]] = []
    unparsable = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            listeners.append(parse_ss_line(line))
        except ValueError:
            unparsable += 1
    unique = {
        (item["protocol"], item["port"], item["address"], item["interface"] or ""): item
        for item in listeners
    }
    return [unique[key] for key in sorted(unique)], unparsable


def collect(ctx: CollectorContext) -> CollectorResult:
    cmd = ctx.commands.run("ss_listening")
    if cmd.status != "ok":
        return CollectorResult(NAME, "error", [], f"ss_listening: {cmd.status}")

    listeners, unparsable = parse_ss(cmd.stdout)
    notes: list[str] = []
    if unparsable:
        notes.append(f"{unparsable} unparsable line(s)")
    if cmd.stdout_truncated:
        notes.append("output truncated")
    unattributed = sum(1 for item in listeners if not item["processes"])
    if unattributed:
        notes.append(f"{unattributed} listener(s) without process attribution (requires root)")

    data = {
        "listeners": listeners,
        "unparsable_lines": unparsable,
        "truncated": cmd.stdout_truncated,
    }
    evidence = [
        Evidence(f"EV-{NAME}-listeners", NAME, f"command:{' '.join(cmd.argv)}", ctx.now(), data)
    ]
    status: CollectorStatus = "partial" if notes else "ok"
    return CollectorResult(NAME, status, evidence, "; ".join(notes) or None)
