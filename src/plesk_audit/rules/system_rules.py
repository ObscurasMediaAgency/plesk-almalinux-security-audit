"""Findings derived from host baseline evidence."""

from __future__ import annotations

from datetime import datetime

from plesk_audit.models import Finding
from plesk_audit.rules.base import EvidenceIndex

EXPECTED_OS_ID = "almalinux"
EXPECTED_OS_VERSION = "9.9"


def os_matches_target(index: EvidenceIndex, now: datetime) -> list[Finding]:
    ev = index.get("EV-system-os-release")
    if ev is None:
        return []
    os_id = ev.data.get("ID", "")
    version = ev.data.get("VERSION_ID", "")
    if os_id == EXPECTED_OS_ID and version == EXPECTED_OS_VERSION:
        return []
    return [
        Finding(
            id="SYS-001",
            title="Operating system differs from the documented audit target",
            domain="system",
            severity="info",
            confidence="high",
            status="needs_review",
            summary=(
                f"Detected {os_id or 'unknown'} {version or 'unknown'}; the toolkit targets "
                f"{EXPECTED_OS_ID} {EXPECTED_OS_VERSION}."
            ),
            evidence_refs=[ev.evidence_id],
            impact="Checks and expectations tuned for the target build may not apply.",
            recommendation="Confirm the correct host was audited and review findings accordingly.",
            detected_at=now,
        )
    ]


def time_synchronization(index: EvidenceIndex, now: datetime) -> list[Finding]:
    ev = index.get("EV-system-time")
    if ev is None:
        return []
    ntp_enabled = ev.data.get("ntp_enabled")
    synchronized = ev.data.get("ntp_synchronized")
    if ntp_enabled is not False and synchronized is not False:
        return []
    state = "disabled" if ntp_enabled is False else "enabled but not synchronized"
    return [
        Finding(
            id="SYS-002",
            title="System clock is not NTP-synchronized",
            domain="system",
            severity="low",
            confidence="high",
            status="observed",
            summary=f"Network time synchronization is {state}.",
            evidence_refs=[ev.evidence_id],
            impact=(
                "Clock drift weakens log correlation during incident triage and can break "
                "TLS validation and time-based one-time passwords."
            ),
            recommendation="Verify chronyd configuration and reachability of the time sources.",
            detected_at=now,
        )
    ]
