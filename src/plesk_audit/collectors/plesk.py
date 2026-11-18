"""Plesk build and extension inventory via read-only Plesk CLI calls.

Privileges: root; otherwise ``error``. Data: product/OS version, build date, revision,
extension IDs, names and versions. Never used: ``plesk installer`` (network access),
``plesk db`` and ``plesk bin admin``/password utilities (secrets, database contents).
"""

from __future__ import annotations

import re
from typing import Any

from plesk_audit.collectors.base import Collection, CollectorContext
from plesk_audit.models import CollectorResult

NAME = "plesk"
_VERSION_RE = re.compile(r"\b(\d+\.\d+\.\d+(?:\.\d+)?)\b")
_VERSION_KEYS = {
    "product version": "product",
    "os version": "os",
    "build date": "build_date",
    "revision": "revision",
}
_EXT_ID_RE = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}")
_EXT_SPLIT_RE = re.compile(r"\s+-\s+|\s{2,}|\t+")


def parse_plesk_version(text: str) -> dict[str, Any]:
    """Parse ``plesk version`` ``Key: value`` lines. VERIFY format on the installed build."""
    data: dict[str, Any] = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        field = _VERSION_KEYS.get(key.strip().lower())
        if sep and field:
            data[field] = value.strip()
    match = _VERSION_RE.search(data.get("product", ""))
    if match is None:
        raise ValueError("no product version")
    data["version"] = match.group(1)
    return dict(sorted(data.items()))


def parse_extensions(text: str) -> tuple[list[dict[str, str | None]], int]:
    """Parse ``plesk bin extension --list``; VERIFY separator format on the installed build."""
    extensions: list[dict[str, str | None]] = []
    unparsable = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = [p.strip() for p in _EXT_SPLIT_RE.split(line.strip()) if p.strip()]
        if not parts or not _EXT_ID_RE.fullmatch(parts[0]):
            unparsable += 1
            continue
        version = parts[-1] if len(parts) >= 3 else None
        extensions.append(
            {"id": parts[0], "name": parts[1] if len(parts) >= 2 else None, "version": version}
        )
    return sorted(extensions, key=lambda e: e["id"] or ""), unparsable


def collect(ctx: CollectorContext) -> CollectorResult:
    c = Collection(NAME, ctx)
    raw = ctx.commands.run("plesk_version")
    if raw.status == "missing":
        c.add("version", "command:plesk version", {"installed": False})
        return c.result()
    result = c.check(raw)
    if result is not None:
        version = c.parse("plesk_version", parse_plesk_version, result.stdout)
        if version is not None:
            c.add("version", "command:plesk version", {"installed": True, **version})

    ext = c.command("plesk_extensions")
    if ext is not None:
        extensions, unparsable = parse_extensions(ext.stdout)
        if unparsable:
            c.note(f"plesk_extensions: {unparsable} unparsable line(s)")
        c.add(
            "extensions",
            "command:plesk bin extension --list",
            {"count": len(extensions), "extensions": extensions},
        )
    return c.result()
