"""Installed packages and pending security advisories.

Privileges: none for the package list; the dnf cache must be readable for advisories.
Data: package NEVRA and install time, kernel packages, advisory IDs/severity/package.
Network: none. ``dnf -C`` only uses cached repository metadata, so advisory results are
only as fresh as the last metadata refresh. dnf may append to its own log files.
"""

from __future__ import annotations

from typing import Any

from plesk_audit.collectors.base import Collection, CollectorContext
from plesk_audit.models import CollectorResult
from plesk_audit.safe_exec import ALLOWED_COMMANDS

NAME = "packages"
KERNEL_PACKAGE = "kernel-core"
ADVISORY_SEVERITIES = ("Critical", "Important", "Moderate", "Low", "Unknown")


def parse_rpm_qa(text: str) -> list[dict[str, Any]]:
    packages: list[dict[str, Any]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != 6 or not parts[1].isdigit() or not parts[5].isdigit():
            raise ValueError("unexpected rpm output")
        name, epoch, version, release, arch, installed = parts
        packages.append(
            {
                "name": name,
                "epoch": int(epoch),
                "version": version,
                "release": release,
                "arch": arch,
                "install_time": int(installed),
            }
        )
    if not packages:
        raise ValueError("no packages")
    packages.sort(key=lambda p: (p["name"], p["arch"], p["version"], p["release"]))
    return packages


def kernel_releases(packages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Installed kernels as ``uname -r`` style releases, newest install first."""
    kernels = [
        {
            "release": f"{p['version']}-{p['release']}.{p['arch']}",
            "install_time": p["install_time"],
        }
        for p in packages
        if p["name"] == KERNEL_PACKAGE
    ]
    return sorted(kernels, key=lambda k: (-k["install_time"], k["release"]))


def parse_updateinfo(text: str) -> tuple[list[dict[str, str]], int]:
    """Parse ``dnf updateinfo list`` lines: ``<advisory> <Severity>/Sec. <package>``."""
    advisories: list[dict[str, str]] = []
    unparsable = 0
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        if len(parts) != 3 or not parts[1].endswith("/Sec."):
            unparsable += 1
            continue
        severity = parts[1].removesuffix("/Sec.")
        advisories.append(
            {
                "advisory": parts[0],
                "severity": severity if severity in ADVISORY_SEVERITIES else "Unknown",
                "package": parts[2],
            }
        )
    unique = {(a["advisory"], a["package"]): a for a in advisories}
    return [unique[k] for k in sorted(unique)], unparsable


def collect(ctx: CollectorContext) -> CollectorResult:
    c = Collection(NAME, ctx)

    rpm = c.command("rpm_packages")
    if rpm is not None:
        packages = c.parse("rpm_packages", parse_rpm_qa, rpm.stdout)
        if packages is not None:
            c.add(
                "installed",
                "command:rpm -qa",
                {
                    "count": len(packages),
                    "kernels": kernel_releases(packages),
                    "packages": packages,
                },
            )

    dnf = c.command("dnf_security_updates")
    if dnf is not None:
        advisories, unparsable = parse_updateinfo(dnf.stdout)
        if unparsable:
            c.note(f"dnf_security_updates: {unparsable} unparsable line(s)")
        by_severity = {
            sev: len({a["advisory"] for a in advisories if a["severity"] == sev})
            for sev in ADVISORY_SEVERITIES
        }
        c.add(
            "security-updates",
            f"command:{' '.join(ALLOWED_COMMANDS['dnf_security_updates'])}",
            {
                "advisory_count": len({a["advisory"] for a in advisories}),
                "package_count": len({a["package"] for a in advisories}),
                "by_severity": by_severity,
                "advisories": advisories,
                "metadata_source": "dnf cache only",
            },
        )
    return c.result()
