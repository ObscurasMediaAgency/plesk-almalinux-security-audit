"""Opt-in external validation of explicitly allow-listed targets.

Only plain TCP connects to a fixed port list and TLS handshakes are performed, sequentially,
with timeouts and a fixed delay between probes. No payloads, banners, credentials or
service-specific requests are sent. Network access is isolated behind :class:`Prober` so tests
never touch the network.
"""

from __future__ import annotations

import errno
import ipaddress
import socket
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, Protocol

from plesk_audit.collectors.base import Collection, CollectorContext
from plesk_audit.config import ExternalConfig
from plesk_audit.models import CollectorResult

PortState = Literal["open", "closed", "filtered", "error"]
LegacyState = Literal["accepted", "rejected", "client_unsupported", "error"]

# (port, service, implicit TLS). STARTTLS services (25/587/110/143/21) are only connect-tested.
PORTS: tuple[tuple[int, str, bool], ...] = (
    (21, "ftp", False),
    (22, "ssh", False),
    (25, "smtp", False),
    (80, "http", False),
    (106, "poppassd", False),
    (110, "pop3", False),
    (143, "imap", False),
    (443, "https", True),
    (465, "smtps", True),
    (587, "submission", False),
    (993, "imaps", True),
    (995, "pop3s", True),
    (3306, "mysql", False),
    (5432, "postgresql", False),
    (6379, "redis", False),
    (8443, "plesk-panel", True),
    (8880, "plesk-panel-http", False),
    (11211, "memcached", False),
)
PROBE_INTERVAL_SECONDS = 0.5
MAX_PROBE_TIMEOUT_SECONDS = 5.0
LEGACY_PROTOCOLS = (("TLSv1", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1))


@dataclass(frozen=True, slots=True)
class TlsInfo:
    verified: bool
    verify_error: str | None
    protocol: str | None
    not_after: datetime | None
    error: str | None = None


class Prober(Protocol):
    def resolve(self, host: str) -> list[str]: ...

    def tcp_connect(self, address: str, port: int, timeout: float) -> PortState: ...

    def tls_handshake(
        self, address: str, port: int, server_name: str | None, timeout: float
    ) -> TlsInfo: ...

    def legacy_tls(
        self, address: str, port: int, version: ssl.TLSVersion, timeout: float
    ) -> LegacyState: ...


def is_public_address(address: str) -> bool:
    return ipaddress.ip_address(address).is_global


class SocketProber:
    """Real network prober using only the standard library."""

    def resolve(self, host: str) -> list[str]:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        return sorted({str(info[4][0]) for info in infos})

    def tcp_connect(self, address: str, port: int, timeout: float) -> PortState:
        try:
            with socket.create_connection((address, port), timeout=timeout):
                return "open"
        except TimeoutError:
            return "filtered"
        except ConnectionRefusedError:
            return "closed"
        except OSError as exc:
            if exc.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH):
                return "filtered"
            return "error"

    def tls_handshake(
        self, address: str, port: int, server_name: str | None, timeout: float
    ) -> TlsInfo:
        ctx = ssl.create_default_context()
        if server_name is None:
            ctx.check_hostname = False
        try:
            with (
                socket.create_connection((address, port), timeout=timeout) as raw,
                ctx.wrap_socket(raw, server_hostname=server_name or address) as tls,
            ):
                cert: dict[str, Any] = tls.getpeercert() or {}
                not_after = cert.get("notAfter")
                expires = (
                    datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), UTC)
                    if isinstance(not_after, str)
                    else None
                )
                return TlsInfo(True, None, tls.version(), expires)
        except ssl.SSLCertVerificationError as exc:
            return TlsInfo(False, str(exc.verify_message or "verification failed"), None, None)
        except (OSError, ssl.SSLError) as exc:
            return TlsInfo(False, None, None, None, error=type(exc).__name__)

    def legacy_tls(
        self, address: str, port: int, version: ssl.TLSVersion, timeout: float
    ) -> LegacyState:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = version
            ctx.maximum_version = version
            # Legacy protocols need SECLEVEL=0 on OpenSSL 3; failure means the client can't test.
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        except (ValueError, ssl.SSLError):
            return "client_unsupported"
        try:
            with (
                socket.create_connection((address, port), timeout=timeout) as raw,
                ctx.wrap_socket(raw) as tls,
            ):
                return "accepted" if tls.version() is not None else "error"
        except ssl.SSLError as exc:
            if "NO_PROTOCOLS_AVAILABLE" in str(exc) or "NO_CIPHERS_AVAILABLE" in str(exc):
                return "client_unsupported"
            return "rejected"
        except ConnectionResetError:
            return "rejected"
        except OSError:
            return "error"


def run_external_checks(
    config: ExternalConfig,
    ctx: CollectorContext,
    prober: Prober,
    *,
    timeout: float,
    sleep: Callable[[float], None] = time.sleep,
    address_policy: Callable[[str], bool] = is_public_address,
) -> CollectorResult:
    """Probe each allow-listed target sequentially and record aggregate evidence."""
    c = Collection("external", ctx)
    if not config.enabled or not config.allowed_targets:
        c.fail("external checks are not enabled")
        return c.result()
    timeout = min(timeout, MAX_PROBE_TIMEOUT_SECONDS)
    probes = 0

    def pace() -> None:
        nonlocal probes
        if probes:
            sleep(PROBE_INTERVAL_SECONDS)
        probes += 1

    ports: list[dict[str, Any]] = []
    tls_results: list[dict[str, Any]] = []
    scanned: list[dict[str, Any]] = []
    for target in config.allowed_targets:
        is_ip = _is_ip(target)
        try:
            addresses = [target] if is_ip else prober.resolve(target)
        except OSError as exc:
            c.note(f"cannot resolve {target}: {type(exc).__name__}")
            continue
        public = [a for a in addresses if address_policy(a)]
        if len(public) != len(addresses):
            c.note(f"{target}: skipped non-public resolved addresses")
        if not public:
            continue
        address = public[0]
        scanned.append({"target": target, "address": address, "resolved": addresses})
        for port, service, implicit_tls in PORTS:
            pace()
            state = prober.tcp_connect(address, port, timeout)
            ports.append(
                {
                    "target": target,
                    "address": address,
                    "port": port,
                    "service": service,
                    "state": state,
                }
            )
            if state != "open" or not implicit_tls or not config.tls_test_enabled:
                continue
            pace()
            info = prober.tls_handshake(address, port, None if is_ip else target, timeout)
            legacy: dict[str, LegacyState] = {}
            for label, version in LEGACY_PROTOCOLS:
                pace()
                legacy[label] = prober.legacy_tls(address, port, version, timeout)
            tls_results.append(
                {
                    "target": target,
                    "port": port,
                    "service": service,
                    "verified": info.verified,
                    "verify_error": info.verify_error,
                    "error": info.error,
                    "protocol": info.protocol,
                    "not_after": info.not_after.isoformat() if info.not_after else None,
                    "days_remaining": (
                        (info.not_after - ctx.now()).days if info.not_after else None
                    ),
                    "legacy": legacy,
                }
            )

    if not scanned:
        c.fail("no allow-listed target could be probed")
        return c.result()
    c.add(
        "scope",
        "configuration",
        {
            "targets": scanned,
            "ports": [p for p, _, _ in PORTS],
            "tls_test_enabled": config.tls_test_enabled,
            "timeout_seconds": timeout,
            "probe_interval_seconds": PROBE_INTERVAL_SECONDS,
            "probes": probes,
        },
    )
    c.add("ports", "tcp connect", {"results": ports})
    if config.tls_test_enabled:
        c.add("tls", "tls handshake", {"results": tls_results})
    if any(p["state"] == "error" for p in ports):
        c.note("some connection attempts failed with local errors")
    return c.result()


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True
