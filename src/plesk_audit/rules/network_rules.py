"""Findings derived from listening-socket evidence."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from types import MappingProxyType
from typing import Any

from plesk_audit.models import Finding
from plesk_audit.rules.base import EvidenceIndex

# Backend services that normally should not be reachable from all interfaces.
BACKEND_TCP_PORTS: Mapping[int, str] = MappingProxyType(
    {
        3306: "MySQL/MariaDB",
        5432: "PostgreSQL",
        6379: "Redis",
        9200: "Elasticsearch/OpenSearch",
        11211: "Memcached",
        27017: "MongoDB",
    }
)


def _listeners(index: EvidenceIndex) -> tuple[str, list[dict[str, Any]]] | None:
    ev = index.get("EV-network-listeners")
    if ev is None:
        return None
    return ev.evidence_id, list(ev.data.get("listeners", []))


def backend_on_wildcard(index: EvidenceIndex, now: datetime) -> list[Finding]:
    found = _listeners(index)
    if found is None:
        return []
    ref, listeners = found
    findings: dict[int, Finding] = {}
    for item in listeners:
        port = item.get("port")
        if item.get("protocol") != "tcp" or item.get("bind_scope") != "wildcard":
            continue
        if not isinstance(port, int) or port not in BACKEND_TCP_PORTS or port in findings:
            continue
        service = BACKEND_TCP_PORTS[port]
        procs = ", ".join(item.get("processes") or []) or "unknown process"
        findings[port] = Finding(
            id=f"NET-001-tcp-{port}",
            title=f"{service} port {port} listens on all interfaces",
            domain="network",
            severity="medium",
            confidence="medium",
            status="needs_review",
            summary=(
                f"TCP port {port} ({service}, {procs}) is bound to a wildcard address. "
                "Actual exposure depends on firewalld and Plesk Firewall rules, which this "
                "run did not evaluate."
            ),
            evidence_refs=[ref],
            impact=(
                "If reachable from the internet, the service is exposed to credential "
                "brute-forcing and exploitation of service vulnerabilities."
            ),
            recommendation=(
                "Verify whether remote access is required. If not, bind to localhost or "
                "restrict access via firewall; for Plesk-managed services use Plesk tooling."
            ),
            detected_at=now,
        )
    return [findings[port] for port in sorted(findings)]


def wildcard_listener_inventory(index: EvidenceIndex, now: datetime) -> list[Finding]:
    found = _listeners(index)
    if found is None:
        return []
    ref, listeners = found
    entries = sorted(
        {
            (str(item["protocol"]), int(item["port"]))
            for item in listeners
            if item.get("bind_scope") == "wildcard"
        }
    )
    if not entries:
        return []
    labels = ", ".join(f"{proto}/{port}" for proto, port in entries)
    return [
        Finding(
            id="NET-002",
            title="Services listening on all interfaces",
            domain="network",
            severity="info",
            confidence="high",
            status="observed",
            summary=f"{len(entries)} wildcard listener(s): {labels}.",
            evidence_refs=[ref],
            impact="Each wildcard listener is potentially reachable unless filtered by a firewall.",
            recommendation="Compare against the expected service inventory for this host.",
            detected_at=now,
        )
    ]
