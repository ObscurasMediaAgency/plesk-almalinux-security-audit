"""Persistence-location metadata: cron, systemd units, profile scripts, ld.so.preload.

Privileges: root for /var/spool/cron; otherwise ``partial``. Data: entry name, type,
permission bits, owner UID/GID, size and modification time of allow-listed directories
(no recursion, no file contents), plus the library paths in /etc/ld.so.preload.
Crontab and unit file contents are not read (they may embed credentials).
"""

from __future__ import annotations

from typing import Any

from plesk_audit.collectors.base import Collection, CollectorContext
from plesk_audit.file_reader import DirEntry
from plesk_audit.models import CollectorResult

NAME = "persistence"
LOCATIONS: dict[str, tuple[str, ...]] = {
    "cron": (
        "/etc/cron.d",
        "/etc/cron.hourly",
        "/etc/cron.daily",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/var/spool/cron",
    ),
    "systemd": ("/etc/systemd/system",),
    "profile": ("/etc/profile.d",),
}


def _entry(e: DirEntry) -> dict[str, Any]:
    return {
        "name": e.name,
        "kind": e.kind,
        "mode": e.mode,
        "uid": e.uid,
        "gid": e.gid,
        "size": e.size,
        "mtime": e.mtime,
    }


def parse_preload(text: str) -> list[str]:
    return sorted(
        {tok for line in text.splitlines() for tok in line.split("#", 1)[0].split() if tok}
    )


def collect(ctx: CollectorContext) -> CollectorResult:
    c = Collection(NAME, ctx)
    for suffix, paths in LOCATIONS.items():
        dirs = []
        for path in paths:
            listing = c.directory(path)
            if listing is not None:
                dirs.append({"path": path, "entries": [_entry(e) for e in listing.entries]})
        if dirs:
            c.add(suffix, "metadata:" + ",".join(paths), {"directories": dirs})

    preload = c.file("/etc/ld.so.preload", missing_ok=True)
    c.add(
        "ld-preload",
        "file:/etc/ld.so.preload",
        {
            "present": preload is not None,
            "libraries": parse_preload(preload.content) if preload else [],
        },
    )
    return c.result()
