from __future__ import annotations

from plesk_audit.collectors import network, system
from plesk_audit.collectors.base import CollectorContext
from plesk_audit.file_reader import FileReadResult
from plesk_audit.safe_exec import CommandResult
from tests.conftest import fixture_text, make_ctx


def test_system_collects_full_baseline(healthy_host_ctx: CollectorContext) -> None:
    result = system.collect(healthy_host_ctx)
    assert result.status == "ok" and result.message is None
    data = {e.evidence_id: e.data for e in result.evidence}
    assert data["EV-system-os-release"]["ID"] == "almalinux"
    assert data["EV-system-os-release"]["VERSION_ID"] == "9.9"
    assert "HOME_URL" not in data["EV-system-os-release"]
    assert data["EV-system-hostname"] == {"hostname": "host.example.test"}
    assert data["EV-system-uptime"] == {"uptime_seconds": 12345}
    assert data["EV-system-kernel"]["machine"] == "x86_64"
    assert data["EV-system-time"] == {
        "ntp_enabled": True,
        "ntp_synchronized": True,
        "timezone": "Europe/Berlin",
    }
    assert data["EV-system-plesk-version"]["version"] == "18.0.82"


def test_system_partial_when_sources_fail() -> None:
    ctx = make_ctx(
        commands={"uname": "unexpected"},
        files={
            "/etc/os-release": fixture_text("os-release-almalinux-9.9.txt"),
            "/proc/uptime": FileReadResult("/proc/uptime", "permission_denied"),
        },
    )
    result = system.collect(ctx)
    assert result.status == "partial"
    assert result.message is not None
    assert "uname: unparsable" in result.message
    assert "/proc/uptime: permission_denied" in result.message
    assert "timedatectl_show: missing" in result.message
    # Missing Plesk is an observation, not a failure.
    plesk = [e for e in result.evidence if e.evidence_id == "EV-system-plesk-version"]
    assert plesk[0].data == {"installed": False}


def test_parse_ss_handles_ipv6_interfaces_and_garbage() -> None:
    listeners, unparsable = network.parse_ss(fixture_text("ss-listening.txt"))
    assert unparsable == 1
    keyed = {(item["protocol"], item["address"], item["port"]): item for item in listeners}
    assert keyed[("tcp", "*", 3306)]["bind_scope"] == "wildcard"
    assert keyed[("tcp", "::", 80)]["bind_scope"] == "wildcard"
    assert keyed[("tcp", "127.0.0.1", 7080)]["bind_scope"] == "loopback"
    assert keyed[("udp", "127.0.0.53", 53)]["interface"] == "lo"
    assert keyed[("tcp", "fe80::1", 546)]["interface"] == "eth0"
    assert keyed[("tcp", "192.0.2.10", 8443)]["bind_scope"] == "specific"
    nginx = keyed[("tcp", "0.0.0.0", 80)]
    assert nginx["processes"] == ["nginx"] and nginx["pids"] == [1200, 1201]


def test_network_output_is_sorted_and_deterministic() -> None:
    text = fixture_text("ss-listening.txt")
    shuffled = "\n".join(reversed(text.splitlines()))
    assert network.parse_ss(text) == network.parse_ss(shuffled)


def test_network_partial_without_process_attribution(healthy_host_ctx: CollectorContext) -> None:
    result = network.collect(healthy_host_ctx)
    assert result.status == "partial"
    assert result.message is not None
    assert "1 unparsable line(s)" in result.message
    assert "2 listener(s) without process attribution" in result.message


def test_network_error_when_ss_fails() -> None:
    failed = CommandResult("ss_listening", ("ss",), "timeout", error="timed out")
    result = network.collect(make_ctx(commands={"ss_listening": failed}))
    assert result.status == "error" and result.evidence == []
