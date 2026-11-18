"""Findings from opt-in external validation evidence (vantage point of the auditor)."""

from __future__ import annotations

from datetime import datetime

from plesk_audit.models import Finding, Severity
from plesk_audit.rules.base import EvidenceIndex

BACKEND_SERVICES = frozenset({"mysql", "postgresql", "redis", "memcached", "poppassd"})
CERT_WARNING_DAYS = 14


def backend_reachable(index: EvidenceIndex, now: datetime) -> list[Finding]:
    ev = index.get("EV-external-ports")
    if ev is None:
        return []
    hits = [
        r
        for r in ev.data.get("results", [])
        if r["state"] == "open" and r["service"] in BACKEND_SERVICES
    ]
    if not hits:
        return []
    listing = ", ".join(f"{r['target']}:{r['port']} ({r['service']})" for r in hits)
    return [
        Finding(
            id="EXT-001",
            title="Backend service reachable from the audit vantage point",
            domain="external",
            severity="high",
            confidence="high",
            status="observed",
            summary=f"TCP connect succeeded to: {listing}.",
            evidence_refs=[ev.evidence_id],
            impact=(
                "Database, cache and helper services exposed to the internet invite brute "
                "force and exploitation of service vulnerabilities."
            ),
            recommendation=(
                "Restrict these ports in firewalld/Plesk Firewall to trusted sources or bind "
                "the services to localhost. Re-test from an untrusted network, since results "
                "depend on the auditor's source address."
            ),
            detected_at=now,
        )
    ]


def legacy_tls_accepted(index: EvidenceIndex, now: datetime) -> list[Finding]:
    ev = index.get("EV-external-tls")
    if ev is None:
        return []
    hits = [
        (r, [proto for proto, state in r["legacy"].items() if state == "accepted"])
        for r in ev.data.get("results", [])
    ]
    hits = [(r, protos) for r, protos in hits if protos]
    if not hits:
        return []
    listing = ", ".join(f"{r['target']}:{r['port']} ({'/'.join(p)})" for r, p in hits)
    return [
        Finding(
            id="EXT-002",
            title="Legacy TLS protocol versions accepted",
            domain="external",
            severity="medium",
            confidence="high",
            status="observed",
            summary=f"Handshakes with deprecated protocol versions succeeded on: {listing}.",
            evidence_refs=[ev.evidence_id],
            impact="TLS 1.0/1.1 are deprecated (RFC 8996) and weaken transport security.",
            recommendation=(
                "Disable TLS 1.0/1.1 in Plesk's server-wide TLS settings and the system crypto "
                "policy; verify mail and panel services separately."
            ),
            detected_at=now,
            references=["https://www.rfc-editor.org/rfc/rfc8996"],
        )
    ]


def certificate_problems(index: EvidenceIndex, now: datetime) -> list[Finding]:
    ev = index.get("EV-external-tls")
    if ev is None:
        return []
    invalid = [r for r in ev.data.get("results", []) if not r["verified"] and r["verify_error"]]
    expiring = [
        r
        for r in ev.data.get("results", [])
        if r["verified"]
        and r["days_remaining"] is not None
        and r["days_remaining"] < CERT_WARNING_DAYS
    ]
    if not invalid and not expiring:
        return []
    parts = [f"{r['target']}:{r['port']} ({r['verify_error']})" for r in invalid]
    parts += [
        f"{r['target']}:{r['port']} (expires in {r['days_remaining']} days)" for r in expiring
    ]
    severity: Severity = "high" if invalid else "medium"
    return [
        Finding(
            id="EXT-003",
            title="TLS certificate invalid or expiring soon",
            domain="external",
            severity=severity,
            confidence="high",
            status="observed",
            summary="Certificate issues: " + ", ".join(parts) + ".",
            evidence_refs=[ev.evidence_id],
            impact=(
                "Clients reject or warn about invalid certificates; users may learn to accept "
                "warnings, enabling interception."
            ),
            recommendation=(
                "Check Let's Encrypt/SSL It! renewal and certificate assignment for the panel, "
                "mail and hosting services. Self-signed certificates on IP-only targets may be "
                "expected; test using the hostname."
            ),
            detected_at=now,
        )
    ]
