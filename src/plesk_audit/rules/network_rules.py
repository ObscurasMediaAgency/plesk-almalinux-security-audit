"""Findings derived from listening-socket evidence."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from types import MappingProxyType
from typing import Any

from plesk_audit.models import Confidence, Finding, Severity
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


# firewalld service definitions covering the backend ports above.
FIREWALLD_SERVICES: Mapping[str, int] = MappingProxyType(
    {
        "mysql": 3306,
        "postgresql": 5432,
        "redis": 6379,
        "elasticsearch": 9200,
        "memcache": 11211,
        "mongodb": 27017,
    }
)


def _port_matches(spec: str, port: int) -> bool:
    ports, _, proto = spec.partition("/")
    if proto and proto != "tcp":
        return False
    low, _, high = ports.partition("-")
    try:
        return int(low) <= port <= int(high or low)
    except ValueError:
        return False


def _zone_allows(zone: Mapping[str, Any], port: int) -> bool:
    return (
        zone.get("target") == "ACCEPT"
        or any(_port_matches(p, port) for p in zone.get("ports", []))
        or any(FIREWALLD_SERVICES.get(s) == port for s in zone.get("services", []))
    )


def _rich_rule_mentions(zone: Mapping[str, Any], port: int) -> bool:
    names = [n for n, p in FIREWALLD_SERVICES.items() if p == port]
    return any(
        f'port="{port}"' in rule or any(f'name="{n}"' in rule for n in names)
        for rule in zone.get("rich_rules", [])
    )


# (severity, confidence, explanation) per exposure class.
_EXPOSURE: Mapping[str, tuple[Severity, Confidence, str]] = MappingProxyType(
    {
        "unknown": (
            "medium",
            "medium",
            "Actual exposure depends on firewall rules, which this run could not evaluate.",
        ),
        "no_firewall": (
            "high",
            "medium",
            "firewalld is not running; other packet filters were not evaluated.",
        ),
        "open": (
            "high",
            "medium",
            "An active firewalld zone bound to interfaces allows this port.",
        ),
        "restricted": (
            "medium",
            "medium",
            "firewalld allows this port only for specific sources or via rich rules.",
        ),
        "filtered": ("low", "medium", "No active firewalld zone allows this port."),
    }
)


def firewall_exposure(index: EvidenceIndex, port: int) -> tuple[str, str | None]:
    """Classify TCP ``port`` against firewalld evidence; returns (class, evidence id)."""
    ev = index.get("EV-security_controls-firewalld")
    if ev is None:
        return "unknown", None
    if not ev.data.get("running"):
        return "no_firewall", ev.evidence_id
    zones = ev.data.get("zones")
    if not zones:
        return "unknown", ev.evidence_id
    relevant = [z for z in zones if z.get("active") or z.get("default")]
    if any(_zone_allows(z, port) and (z.get("default") or z.get("interfaces")) for z in relevant):
        return "open", ev.evidence_id
    if any(_zone_allows(z, port) or _rich_rule_mentions(z, port) for z in relevant):
        return "restricted", ev.evidence_id
    return "filtered", ev.evidence_id


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
        exposure, fw_ref = firewall_exposure(index, port)
        severity, confidence, explanation = _EXPOSURE[exposure]
        findings[port] = Finding(
            id=f"NET-001-tcp-{port}",
            title=f"{service} port {port} listens on all interfaces",
            domain="network",
            severity=severity,
            confidence=confidence,
            status="needs_review",
            summary=(
                f"TCP port {port} ({service}, {procs}) is bound to a wildcard address. "
                f"{explanation} Upstream or provider firewalls were not evaluated."
            ),
            evidence_refs=[ref] + ([fw_ref] if fw_ref else []),
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
