"""Host baseline: OS identification, kernel, hostname, uptime, time sync, Plesk version.

Privileges: none required. Data: os-release identifiers, kernel release, hostname,
uptime, NTP state, Plesk version string. No secrets are involved.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from plesk_audit.collectors.base import CollectorContext, aggregate_status
from plesk_audit.models import CollectorResult, Evidence

NAME = "system"
PLESK_VERSION_FILE = "/usr/local/psa/version"  # VERIFY against the installed build
_OS_RELEASE_KEYS = ("ID", "ID_LIKE", "NAME", "PLATFORM_ID", "PRETTY_NAME", "VERSION_ID")
_TIMEDATE_KEYS = {
    "Timezone": "timezone",
    "NTP": "ntp_enabled",
    "NTPSynchronized": "ntp_synchronized",
}


def parse_os_release(text: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for line in text.splitlines():
        key, sep, value = line.strip().partition("=")
        if not sep or key not in _OS_RELEASE_KEYS:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        result[key] = value
    if "ID" not in result:
        raise ValueError("os-release without ID")
    return dict(sorted(result.items()))


def parse_hostname(text: str) -> dict[str, Any]:
    hostname = text.strip()
    if not hostname:
        raise ValueError("empty hostname")
    return {"hostname": hostname}


def parse_uptime(text: str) -> dict[str, Any]:
    return {"uptime_seconds": int(float(text.split()[0]))}


def parse_uname(text: str) -> dict[str, Any]:
    parts = text.split()
    if len(parts) != 3:
        raise ValueError("unexpected uname output")
    return {"kernel_name": parts[0], "kernel_release": parts[1], "machine": parts[2]}


def _yes_no(value: str) -> bool | None:
    return {"yes": True, "no": False}.get(value.strip().lower())


def parse_timedatectl(text: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if not sep or key not in _TIMEDATE_KEYS:
            continue
        field = _TIMEDATE_KEYS[key]
        result[field] = value.strip() if field == "timezone" else _yes_no(value)
    if not result:
        raise ValueError("no timedatectl properties")
    return dict(sorted(result.items()))


def parse_plesk_version(text: str) -> dict[str, Any]:
    # Assumed form: "18.0.82 AlmaLinux 9 <build-id>". VERIFY against the installed build.
    lines = text.strip().splitlines()
    if not lines or not lines[0].strip():
        raise ValueError("empty Plesk version file")
    first = lines[0].strip()
    return {"installed": True, "raw": first, "version": first.split()[0]}


Parser = Callable[[str], dict[str, Any]]


def collect(ctx: CollectorContext) -> CollectorResult:
    evidence: list[Evidence] = []
    failures: list[str] = []

    def record(suffix: str, source: str, text: str, parse: Parser, label: str) -> None:
        try:
            data = parse(text)
        except (ValueError, IndexError):
            failures.append(f"{label}: unparsable")
            return
        evidence.append(Evidence(f"EV-{NAME}-{suffix}", NAME, source, ctx.now(), data))

    file_parsers: tuple[tuple[str, str, Parser], ...] = (
        ("os-release", "/etc/os-release", parse_os_release),
        ("hostname", "/proc/sys/kernel/hostname", parse_hostname),
        ("uptime", "/proc/uptime", parse_uptime),
    )
    for suffix, path, parse in file_parsers:
        res = ctx.files.read(path)
        if res.status == "ok":
            record(suffix, f"file:{path}", res.content, parse, path)
        else:
            failures.append(f"{path}: {res.status}")

    cmd_parsers: tuple[tuple[str, str, Parser], ...] = (
        ("kernel", "uname", parse_uname),
        ("time", "timedatectl_show", parse_timedatectl),
    )
    for suffix, name, cmd_parse in cmd_parsers:
        cmd = ctx.commands.run(name)
        if cmd.status == "ok":
            record(suffix, f"command:{' '.join(cmd.argv)}", cmd.stdout, cmd_parse, name)
        else:
            failures.append(f"{name}: {cmd.status}")

    plesk = ctx.files.read(PLESK_VERSION_FILE)
    source = f"file:{PLESK_VERSION_FILE}"
    if plesk.status == "ok":
        record("plesk-version", source, plesk.content, parse_plesk_version, PLESK_VERSION_FILE)
    elif plesk.status == "missing":
        # Absence is an observation (e.g. a test VM without Plesk), not a collector failure.
        evidence.append(
            Evidence(f"EV-{NAME}-plesk-version", NAME, source, ctx.now(), {"installed": False})
        )
    else:
        failures.append(f"{PLESK_VERSION_FILE}: {plesk.status}")

    status = aggregate_status(len(evidence), len(failures))
    return CollectorResult(NAME, status, evidence, "; ".join(failures) or None)
