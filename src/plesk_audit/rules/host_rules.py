"""Findings for packages, services and local accounts."""

from __future__ import annotations

from datetime import datetime

from plesk_audit.models import Finding
from plesk_audit.rules.base import EvidenceIndex


def security_updates(index: EvidenceIndex, now: datetime) -> list[Finding]:
    ev = index.get("EV-packages-security-updates")
    if ev is None or not ev.data.get("advisory_count"):
        return []
    by_sev = ev.data.get("by_severity", {})
    urgent = by_sev.get("Critical", 0) + by_sev.get("Important", 0)
    breakdown = ", ".join(f"{k}: {v}" for k, v in by_sev.items() if v)
    return [
        Finding(
            id="PKG-001",
            title="Security advisories pending for installed packages",
            domain="packages",
            severity="medium" if urgent else "low",
            confidence="medium",
            status="observed",
            summary=(
                f"{ev.data['advisory_count']} security advisory(ies) affecting "
                f"{ev.data.get('package_count', 0)} package(s) ({breakdown}). Based on cached "
                "repository metadata, which may be outdated."
            ),
            evidence_refs=[ev.evidence_id],
            impact=(
                "Unpatched packages may contain known vulnerabilities. Actual exploitability "
                "depends on whether the affected component is used and exposed."
            ),
            recommendation=(
                "Review the advisories (dnf updateinfo info <id>) and apply updates in a "
                "maintenance window after a backup; Plesk components should be updated via "
                "Plesk tooling."
            ),
            detected_at=now,
        )
    ]


def kernel_reboot_pending(index: EvidenceIndex, now: datetime) -> list[Finding]:
    pkgs = index.get("EV-packages-installed")
    kernel = index.get("EV-system-kernel")
    if pkgs is None or kernel is None:
        return []
    kernels = pkgs.data.get("kernels") or []
    running = kernel.data.get("kernel_release")
    if not kernels or not running or kernels[0]["release"] == running:
        return []
    return [
        Finding(
            id="PKG-002",
            title="Running kernel is not the most recently installed kernel",
            domain="packages",
            severity="low",
            confidence="medium",
            status="observed",
            summary=(
                f"Running {running}; most recently installed kernel is {kernels[0]['release']}."
            ),
            evidence_refs=[pkgs.evidence_id, kernel.evidence_id],
            impact="Kernel security fixes installed on disk are not active until a reboot.",
            recommendation="Plan a reboot in a maintenance window if the newer kernel is intended.",
            detected_at=now,
        )
    ]


def failed_units(index: EvidenceIndex, now: datetime) -> list[Finding]:
    ev = index.get("EV-services-units")
    failed = ev.data.get("failed") if ev else None
    if ev is None or not failed:
        return []
    return [
        Finding(
            id="SVC-001",
            title="Failed systemd units",
            domain="services",
            severity="low",
            confidence="high",
            status="observed",
            summary=f"{len(failed)} failed unit(s): {', '.join(failed)}.",
            evidence_refs=[ev.evidence_id],
            impact=(
                "Failed units may indicate broken security services (e.g. backups, "
                "fail2ban, updates) or unexpected changes."
            ),
            recommendation="Review each unit with systemctl status and journalctl -u <unit>.",
            detected_at=now,
        )
    ]


def extra_uid0(index: EvidenceIndex, now: datetime) -> list[Finding]:
    ev = index.get("EV-accounts-local")
    extra = [n for n in (ev.data.get("uid0") or []) if n != "root"] if ev else []
    if ev is None or not extra:
        return []
    return [
        Finding(
            id="ACC-001",
            title="Additional accounts with UID 0",
            domain="accounts",
            severity="high",
            confidence="high",
            status="needs_review",
            summary=f"Accounts other than root have UID 0: {', '.join(extra)}.",
            evidence_refs=[ev.evidence_id],
            impact=(
                "Every UID 0 account has full root privileges. Unexpected UID 0 accounts are "
                "a common persistence technique."
            ),
            recommendation=(
                "Verify who created these accounts and why. If unexpected, treat as a potential "
                "compromise and preserve evidence before changing anything."
            ),
            detected_at=now,
        )
    ]


def sudo_nopasswd(index: EvidenceIndex, now: datetime) -> list[Finding]:
    ev = index.get("EV-accounts-sudoers")
    if ev is None:
        return []
    rules = [
        f"{f['path']}: {r['line']}"
        for f in ev.data.get("files", [])
        for r in f.get("rules", [])
        if r.get("nopasswd")
    ]
    if not rules:
        return []
    return [
        Finding(
            id="ACC-002",
            title="sudo rules without password",
            domain="accounts",
            severity="medium",
            confidence="high",
            status="needs_review",
            summary=f"{len(rules)} NOPASSWD rule(s): " + "; ".join(rules[:10]),
            evidence_refs=[ev.evidence_id],
            impact=(
                "A compromised account covered by NOPASSWD can escalate to the granted "
                "privileges without knowing a password."
            ),
            recommendation="Confirm each rule is required and limited to specific commands.",
            detected_at=now,
        )
    ]


def root_authorized_keys(index: EvidenceIndex, now: datetime) -> list[Finding]:
    ev = index.get("EV-accounts-authorized-keys")
    if ev is None:
        return []
    root = [f for f in ev.data.get("files", []) if f.get("user") == "root" and f["key_count"]]
    if not root:
        return []
    total = sum(f["key_count"] for f in root)
    unrestricted = sum(f["key_count"] - f["restricted_keys"] for f in root)
    return [
        Finding(
            id="ACC-003",
            title="SSH keys authorized for root",
            domain="accounts",
            severity="info",
            confidence="high",
            status="needs_review",
            summary=f"{total} key(s) authorized for root, {unrestricted} without from=/command=.",
            evidence_refs=[ev.evidence_id],
            impact="Each authorized key grants direct root access if its private key leaks.",
            recommendation=(
                "Compare the keys against the list of authorized administrators and remove "
                "unknown or stale keys through your change process."
            ),
            detected_at=now,
        )
    ]
