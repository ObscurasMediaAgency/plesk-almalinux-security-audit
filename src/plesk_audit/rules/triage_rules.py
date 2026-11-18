"""Compromise-triage findings from aggregated log and persistence evidence.

These are review pointers, not verdicts: log data can be incomplete or tampered with.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from plesk_audit.models import Finding
from plesk_audit.rules.base import EvidenceIndex

PASSWORD_METHODS = frozenset({"password", "keyboard-interactive/pam"})
BRUTE_FORCE_TOTAL = 100
BRUTE_FORCE_PER_IP = 20
SUSPICIOUS_FAILURES_BEFORE_SUCCESS = 5
RECENT_CHANGE_DAYS = 7
USER_SPOOL = "/var/spool/cron"


def root_password_login(index: EvidenceIndex, now: datetime) -> list[Finding]:
    ev = index.get("EV-logs-ssh-auth")
    if ev is None:
        return []
    hits = [
        a
        for a in ev.data.get("accepted", [])
        if a["user"] == "root" and a["method"] in PASSWORD_METHODS
    ]
    if not hits:
        return []
    sources = ", ".join(f"{a['ip']} ({a['count']}x)" for a in hits)
    return [
        Finding(
            id="LOG-001",
            title="Successful root login with password",
            domain="logs",
            severity="medium",
            confidence="high",
            status="needs_review",
            summary=f"Root password logins in the lookback window from: {sources}.",
            evidence_refs=[ev.evidence_id],
            impact=(
                "Password-based root access is the main target of SSH brute-force attacks; "
                "unexpected sources may indicate compromised credentials."
            ),
            recommendation=(
                "Confirm each source IP belongs to an administrator. If not, treat as a "
                "potential compromise and preserve evidence before changing anything."
            ),
            detected_at=now,
        )
    ]


def ssh_brute_force(index: EvidenceIndex, now: datetime) -> list[Finding]:
    ev = index.get("EV-logs-ssh-auth")
    if ev is None:
        return []
    total = ev.data.get("failed_total", 0) + ev.data.get("invalid_user_total", 0)
    top = ev.data.get("failed_by_ip") or []
    heavy = [t for t in top if t["count"] >= BRUTE_FORCE_PER_IP]
    if total < BRUTE_FORCE_TOTAL and not heavy:
        return []
    listing = ", ".join(f"{t['ip']} ({t['count']})" for t in (heavy or top)[:5])
    return [
        Finding(
            id="LOG-002",
            title="SSH brute-force activity",
            domain="logs",
            severity="low",
            confidence="high",
            status="observed",
            summary=f"{total} failed/invalid SSH attempts in the window; top sources: {listing}.",
            evidence_refs=[ev.evidence_id],
            impact=(
                "Background noise for internet-facing hosts, but weak passwords may be guessed."
            ),
            recommendation=("Ensure Fail2Ban covers SSH and prefer key-based authentication."),
            detected_at=now,
        )
    ]


def login_after_failures(index: EvidenceIndex, now: datetime) -> list[Finding]:
    ev = index.get("EV-logs-ssh-auth")
    if ev is None:
        return []
    failures = {t["ip"]: t["count"] for t in ev.data.get("failed_by_ip", [])}
    hits = [
        a
        for a in ev.data.get("accepted", [])
        if failures.get(a["ip"], 0) >= SUSPICIOUS_FAILURES_BEFORE_SUCCESS
    ]
    if not hits:
        return []
    detail = "; ".join(
        f"{a['user']} from {a['ip']} via {a['method']} after {failures[a['ip']]} failures"
        for a in hits
    )
    return [
        Finding(
            id="LOG-003",
            title="Successful SSH login from a source with many failures",
            domain="logs",
            severity="medium",
            confidence="low",
            status="needs_review",
            summary=f"{detail}.",
            evidence_refs=[ev.evidence_id],
            impact="A successful login following repeated failures can indicate guessed credentials.",
            recommendation=(
                "Verify with the account owner. Failures and the success may be unrelated "
                "(e.g. shared NAT address or a mistyped password)."
            ),
            detected_at=now,
        )
    ]


def mail_brute_force(index: EvidenceIndex, now: datetime) -> list[Finding]:
    ev = index.get("EV-logs-mail-auth")
    if ev is None or ev.data.get("failed_total", 0) < BRUTE_FORCE_TOTAL:
        return []
    top = ", ".join(f"{t['ip']} ({t['count']})" for t in ev.data.get("failed_by_ip", [])[:5])
    return [
        Finding(
            id="LOG-004",
            title="Mail authentication brute-force activity",
            domain="logs",
            severity="low",
            confidence="high",
            status="observed",
            summary=f"{ev.data['failed_total']} failed SASL/IMAP/POP3 logins; top sources: {top}.",
            evidence_refs=[ev.evidence_id],
            impact="Guessed mailbox passwords are commonly abused for spam relaying.",
            recommendation="Ensure Fail2Ban mail jails are active and enforce strong mailbox passwords.",
            detected_at=now,
        )
    ]


def ld_preload(index: EvidenceIndex, now: datetime) -> list[Finding]:
    ev = index.get("EV-persistence-ld-preload")
    if ev is None or not ev.data.get("libraries"):
        return []
    return [
        Finding(
            id="PER-001",
            title="Libraries are preloaded system-wide via /etc/ld.so.preload",
            domain="persistence",
            severity="high",
            confidence="medium",
            status="needs_review",
            summary=f"Preloaded: {', '.join(ev.data['libraries'])}.",
            evidence_refs=[ev.evidence_id],
            impact=(
                "Every dynamically linked process loads these libraries; this is a known "
                "rootkit technique, though some security agents use it legitimately."
            ),
            recommendation=(
                "Identify the owning package (rpm -qf). If unknown, treat as a potential "
                "compromise and preserve evidence."
            ),
            detected_at=now,
        )
    ]


def _entries(index: EvidenceIndex) -> list[tuple[str, str, dict[str, Any]]]:
    found = []
    for suffix in ("cron", "systemd", "profile"):
        ev = index.get(f"EV-persistence-{suffix}")
        if ev is None:
            continue
        for directory in ev.data.get("directories", []):
            for entry in directory.get("entries", []):
                found.append((ev.evidence_id, directory["path"], entry))
    return found


def recent_persistence_changes(index: EvidenceIndex, now: datetime) -> list[Finding]:
    since = now - timedelta(days=RECENT_CHANGE_DAYS)
    hits = [
        (ref, f"{path}/{e['name']}")
        for ref, path, e in _entries(index)
        if e["kind"] in ("file", "symlink") and e["mtime"] >= since
    ]
    if not hits:
        return []
    names = [h[1] for h in hits]
    return [
        Finding(
            id="PER-002",
            title="Recently modified entries in persistence locations",
            domain="persistence",
            severity="info",
            confidence="low",
            status="needs_review",
            summary=(
                f"{len(names)} entr(y/ies) modified in the last {RECENT_CHANGE_DAYS} days: "
                + ", ".join(names[:20])
                + (" ..." if len(names) > 20 else "")
            ),
            evidence_refs=sorted({h[0] for h in hits}),
            impact="New cron jobs, units or profile scripts are common persistence mechanisms.",
            recommendation="Match each entry against recent package updates and planned changes.",
            detected_at=now,
        )
    ]


def unsafe_persistence_permissions(index: EvidenceIndex, now: datetime) -> list[Finding]:
    hits = []
    for ref, path, e in _entries(index):
        if e["kind"] == "symlink":
            continue
        world_writable = int(e["mode"], 8) & 0o002
        foreign_owner = e["uid"] != 0 and path != USER_SPOOL
        if world_writable or foreign_owner:
            reason = "world-writable" if world_writable else f"owned by UID {e['uid']}"
            hits.append((ref, f"{path}/{e['name']} ({reason})"))
    if not hits:
        return []
    return [
        Finding(
            id="PER-003",
            title="Persistence locations writable by non-root users",
            domain="persistence",
            severity="medium",
            confidence="high",
            status="needs_review",
            summary="; ".join(h[1] for h in hits[:20]),
            evidence_refs=sorted({h[0] for h in hits}),
            impact=(
                "Entries modifiable by non-root users can be turned into root-level code "
                "execution or persistence."
            ),
            recommendation="Verify ownership via rpm -qf and restore root ownership/0644 or stricter.",
            detected_at=now,
        )
    ]
