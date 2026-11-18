"""Findings for the Plesk installation."""

from __future__ import annotations

from datetime import datetime

from plesk_audit.models import Finding
from plesk_audit.rules.base import EvidenceIndex

EXPECTED_PLESK_RELEASE = "18.0.82"


def plesk_matches_target(index: EvidenceIndex, now: datetime) -> list[Finding]:
    # Prefer the CLI (full build) and fall back to the version file from `system`.
    ev = index.get("EV-plesk-version") or index.get("EV-system-plesk-version")
    if ev is None:
        return []
    if not ev.data.get("installed"):
        detected = "Plesk is not installed"
    else:
        version = str(ev.data.get("version", ""))
        if version.split(".")[:3] == EXPECTED_PLESK_RELEASE.split("."):
            return []
        detected = f"Detected Plesk {version or 'unknown version'}"
    return [
        Finding(
            id="PLK-001",
            title="Plesk release differs from the documented audit target",
            domain="plesk",
            severity="info",
            confidence="high",
            status="needs_review",
            summary=f"{detected}; the toolkit targets Plesk Obsidian {EXPECTED_PLESK_RELEASE}.",
            evidence_refs=[ev.evidence_id],
            impact="Plesk-specific checks and paths may not apply to this release.",
            recommendation=(
                "Confirm the correct host was audited. Keep Plesk on a supported release and "
                "update it through Plesk tooling."
            ),
            detected_at=now,
        )
    ]
