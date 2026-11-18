"""Bounded log triage over allow-listed syslog files (profile ``triage`` only).

Privileges: root (files are 0600). Data: aggregated counts only — SSH failures per source
IP and per existing account, accepted logins (user, IP, method), sudo use per invoking
user, mail SASL failures per IP. Never stored: message bodies, sudo commands, usernames
from invalid-user attempts (often mistyped passwords), passwords or tokens.
Only the configured sources and only the last ``max_file_bytes``/``max_lines_per_source``
are read; rotated files are not considered.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, tzinfo
from typing import Any

from plesk_audit.collectors.base import Collection, CollectorContext
from plesk_audit.models import CollectorResult

NAME = "logs"
TOP_N = 20
MAX_ACCEPTED = 100
_MONTHS = {
    m: i
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1
    )
}
_SYSLOG_TS = re.compile(r"([A-Z][a-z]{2}) {1,2}(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) ")
_ISO_TS = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})) ")
_USER = r"[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}"
_IP = r"[0-9A-Fa-f:.]{2,45}"
_FAILED = re.compile(rf"sshd\[\d+\]: Failed \S+ for (invalid user )?(?:(\S*) )?from ({_IP}) port")
_INVALID = re.compile(rf"sshd\[\d+\]: Invalid user .* from ({_IP})(?: port|$)")
_ACCEPTED = re.compile(rf"sshd\[\d+\]: Accepted (\S+) for ({_USER}) from ({_IP}) port")
_SUDO = re.compile(rf"sudo(?:\[\d+\])?: +({_USER}) : .*COMMAND=")
_SASL = re.compile(
    rf"postfix/\S+\[\d+\]: warning: [^\[\s]*\[({_IP})\]: SASL \S+ authentication failed"
)
_DOVECOT = re.compile(rf"dovecot(?:\[\d+\])?: .*auth failed.*rip=({_IP})")


def parse_timestamp(line: str, now: datetime, local_tz: tzinfo) -> datetime | None:
    """Return the line's timestamp; classic syslog lines have no year or zone."""
    iso = _ISO_TS.match(line)
    if iso:
        return datetime.fromisoformat(iso.group(1))
    m = _SYSLOG_TS.match(line)
    if not m or m.group(1) not in _MONTHS:
        return None
    local_now = now.astimezone(local_tz)
    try:
        ts = datetime(
            local_now.year,
            _MONTHS[m.group(1)],
            int(m.group(2)),
            int(m.group(3)),
            int(m.group(4)),
            int(m.group(5)),
            tzinfo=local_tz,
        )
    except ValueError:
        return None
    if ts > now + timedelta(days=1):
        ts = ts.replace(year=ts.year - 1)
    return ts


def _ip(text: str) -> str | None:
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


@dataclass
class LogStats:
    failed_by_ip: Counter[str] = field(default_factory=Counter)
    failed_by_user: Counter[str] = field(default_factory=Counter)
    failed_total: int = 0
    invalid_user_total: int = 0
    accepted: dict[tuple[str, str, str], list[Any]] = field(default_factory=dict)
    sudo_by_user: Counter[str] = field(default_factory=Counter)
    mail_failed_by_ip: Counter[str] = field(default_factory=Counter)

    def feed(self, line: str, ts: datetime) -> None:
        if m := _FAILED.search(line):
            self.failed_total += 1
            if ip := _ip(m.group(3)):
                self.failed_by_ip[ip] += 1
            # The matching "Invalid user" line is counted separately.
            if not m.group(1) and m.group(2):
                self.failed_by_user[m.group(2)] += 1
        elif m := _INVALID.search(line):
            self.invalid_user_total += 1
        elif m := _ACCEPTED.search(line):
            ip = _ip(m.group(3))
            if ip is None:
                return
            key = (m.group(2), ip, m.group(1))
            entry = self.accepted.setdefault(key, [0, ts, ts])
            entry[0] += 1
            entry[1] = min(entry[1], ts)
            entry[2] = max(entry[2], ts)
        elif m := _SUDO.search(line):
            self.sudo_by_user[m.group(1)] += 1
        elif ((m := _SASL.search(line)) or (m := _DOVECOT.search(line))) and (
            ip := _ip(m.group(1))
        ):
            self.mail_failed_by_ip[ip] += 1


def _top(counter: Counter[str], key: str) -> list[dict[str, Any]]:
    return [{key: k, "count": v} for k, v in sorted(counter.items(), key=lambda i: (-i[1], i[0]))][
        :TOP_N
    ]


def local_timezone() -> tzinfo:
    tz = datetime.now().astimezone().tzinfo
    assert tz is not None
    return tz


def collect(ctx: CollectorContext) -> CollectorResult:
    c = Collection(NAME, ctx)
    settings = ctx.logs
    if settings is None:
        c.fail("no log settings in context")
        return c.result()
    now = ctx.now()
    tz = local_timezone()
    window_start = now - timedelta(hours=settings.lookback_hours)
    stats = LogStats()
    sources: list[dict[str, Any]] = []
    for path in settings.sources:
        read = c.file(path, missing_ok=True, tail=True)
        if read is None:
            continue
        lines = read.content.splitlines()
        if read.truncated and lines:
            lines = lines[1:]  # first line may be cut in the middle
        considered = lines[-settings.max_lines_per_source :]
        in_window = no_ts = 0
        earliest: datetime | None = None
        for line in considered:
            ts = parse_timestamp(line, now, tz)
            if ts is None:
                no_ts += 1
                continue
            earliest = ts if earliest is None else min(earliest, ts)
            if window_start <= ts <= now + timedelta(minutes=5):
                in_window += 1
                stats.feed(line, ts)
        limited = read.truncated or len(lines) > len(considered)
        covers = earliest is not None and (earliest <= window_start or not limited)
        if not covers and considered:
            c.note(f"{path}: read limit reached before start of lookback window")
        sources.append(
            {
                "path": path,
                "lines_considered": len(considered),
                "lines_in_window": in_window,
                "lines_without_timestamp": no_ts,
                "read_limited": limited,
                "earliest_timestamp": earliest,
                "covers_window": covers,
            }
        )
    if not sources:
        if not c.failures:
            c.note("none of the configured log sources exist")
        return c.result()

    window = {"window_start": window_start, "window_end": now}
    c.add("sources", "file:" + ",".join(settings.sources), {**window, "sources": sources})
    accepted = [
        {"user": u, "ip": ip, "method": m, "count": v[0], "first": v[1], "last": v[2]}
        for (u, ip, m), v in sorted(stats.accepted.items())
    ]
    c.add(
        "ssh-auth",
        "file:/var/log/secure",
        {
            **window,
            "failed_total": stats.failed_total,
            "invalid_user_total": stats.invalid_user_total,
            "failed_by_ip": _top(stats.failed_by_ip, "ip"),
            "failed_by_user": _top(stats.failed_by_user, "user"),
            "accepted": accepted[:MAX_ACCEPTED],
            "accepted_truncated": len(accepted) > MAX_ACCEPTED,
        },
    )
    c.add("sudo", "file:/var/log/secure", {**window, "by_user": _top(stats.sudo_by_user, "user")})
    c.add(
        "mail-auth",
        "file:/var/log/maillog",
        {
            **window,
            "failed_total": sum(stats.mail_failed_by_ip.values()),
            "failed_by_ip": _top(stats.mail_failed_by_ip, "ip"),
        },
    )
    return c.result()
