from __future__ import annotations

import copy
import ssl
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml

from plesk_audit import cli
from plesk_audit.config import ConfigError, ExternalConfig, parse_config
from plesk_audit.external import (
    PORTS,
    PROBE_INTERVAL_SECONDS,
    LegacyState,
    PortState,
    TlsInfo,
    is_public_address,
    run_external_checks,
)
from plesk_audit.models import Evidence
from plesk_audit.rules import evaluate
from plesk_audit.runner import external, run_external
from tests.conftest import FIXED_NOW, make_ctx
from tests.test_config import base

TARGET = "audit.example.test"
ADDRESS = "198.51.100.7"


def enabled_raw(**external_overrides: Any) -> dict[str, Any]:
    raw = copy.deepcopy(base())
    raw["audit"]["external_checks"] = True
    raw["external"] = {
        "allowed_targets": [TARGET],
        "nmap_enabled": False,
        "tls_test_enabled": True,
    } | external_overrides
    return raw


class FakeProber:
    def __init__(
        self,
        open_ports: set[int],
        *,
        addresses: list[str] | None = None,
        tls: TlsInfo | None = None,
        legacy: LegacyState = "rejected",
    ) -> None:
        self.open_ports = open_ports
        self.addresses = addresses if addresses is not None else [ADDRESS]
        self.tls = tls or TlsInfo(True, None, "TLSv1.3", FIXED_NOW + timedelta(days=60))
        self.legacy = legacy
        self.calls: list[tuple[str, str, int]] = []

    def resolve(self, host: str) -> list[str]:
        self.calls.append(("resolve", host, 0))
        return self.addresses

    def tcp_connect(self, address: str, port: int, timeout: float) -> PortState:
        assert timeout <= 5
        self.calls.append(("tcp", address, port))
        return "open" if port in self.open_ports else "filtered"

    def tls_handshake(
        self, address: str, port: int, server_name: str | None, timeout: float
    ) -> TlsInfo:
        assert server_name == TARGET
        self.calls.append(("tls", address, port))
        return self.tls

    def legacy_tls(
        self, address: str, port: int, version: ssl.TLSVersion, timeout: float
    ) -> LegacyState:
        self.calls.append(("legacy", address, port))
        return self.legacy


def allow_documentation(address: str) -> bool:
    return address.startswith("198.51.100.")


def probe(prober: FakeProber, config: ExternalConfig | None = None) -> Any:
    sleeps: list[float] = []
    result = run_external_checks(
        config or parse_config(enabled_raw()).external,
        make_ctx(),
        prober,
        timeout=30,
        sleep=sleeps.append,
        address_policy=allow_documentation,
    )
    return result, sleeps


def test_config_accepts_explicit_hostname_and_defaults_to_disabled() -> None:
    assert parse_config(base()).external == ExternalConfig(False, (), False)
    config = parse_config(enabled_raw(allowed_targets=["Audit.Example.Test."]))
    assert config.external == ExternalConfig(True, (TARGET,), True)


@pytest.mark.parametrize(
    "targets",
    [
        [],
        ["192.0.2.0/24"],
        ["10.0.0.5"],
        ["127.0.0.1"],
        ["2001:db8::1"],
        ["*.example.test"],
        ["https://audit.example.test"],
        ["audit.example.test:8443"],
        ["localhost"],
        [" audit.example.test"],
        [TARGET, TARGET],
        [f"h{i}.example.test" for i in range(6)],
    ],
)
def test_config_rejects_unsafe_targets(targets: list[str]) -> None:
    with pytest.raises(ConfigError):
        parse_config(enabled_raw(allowed_targets=targets))


def test_config_requires_explicit_opt_in_and_never_nmap() -> None:
    raw = enabled_raw()
    raw["audit"]["external_checks"] = False
    with pytest.raises(ConfigError, match="opt-in"):
        parse_config(raw)
    with pytest.raises(ConfigError, match="nmap"):
        parse_config(enabled_raw(nmap_enabled=True))


def test_default_address_policy_rejects_non_public() -> None:
    assert not is_public_address("10.1.2.3")
    assert not is_public_address("198.51.100.7")
    assert not is_public_address("::1")


def test_probes_fixed_ports_with_rate_limit_and_tls() -> None:
    prober = FakeProber({22, 443, 3306}, legacy="accepted")
    result, sleeps = probe(prober)
    assert result.status == "ok"
    tcp = [c for c in prober.calls if c[0] == "tcp"]
    assert [c[2] for c in tcp] == [p for p, _, _ in PORTS]
    assert {c[1] for c in prober.calls if c[0] != "resolve"} == {ADDRESS}
    total = sum(1 for c in prober.calls if c[0] != "resolve")
    assert sleeps == [PROBE_INTERVAL_SECONDS] * (total - 1)
    evidence = {e.evidence_id: e.data for e in result.evidence}
    assert evidence["EV-external-scope"]["timeout_seconds"] == 5
    tls = evidence["EV-external-tls"]["results"]
    assert [(r["port"], r["days_remaining"], r["legacy"]["TLSv1"]) for r in tls] == [
        (443, 60, "accepted")
    ]


def test_non_public_resolution_is_never_probed() -> None:
    prober = FakeProber({443}, addresses=["10.0.0.5"])
    result, _ = probe(prober)
    assert result.status == "error"
    assert [c[0] for c in prober.calls] == ["resolve"]
    assert "non-public" in (result.message or "")


def test_tls_disabled_skips_handshakes() -> None:
    prober = FakeProber({443, 8443})
    config = parse_config(enabled_raw(tls_test_enabled=False)).external
    result, _ = probe(prober, config)
    assert {c[0] for c in prober.calls} == {"resolve", "tcp"}
    assert "EV-external-tls" not in {e.evidence_id for e in result.evidence}


def _ext(evidence_id: str, results: list[dict[str, Any]]) -> Evidence:
    return Evidence(evidence_id, "external", "test", FIXED_NOW, {"results": results})


def _tls(**overrides: Any) -> dict[str, Any]:
    return {
        "target": TARGET,
        "port": 443,
        "verified": True,
        "verify_error": None,
        "days_remaining": 60,
        "legacy": {"TLSv1": "rejected", "TLSv1.1": "client_unsupported"},
    } | overrides


@pytest.mark.parametrize(
    ("evidence", "expected"),
    [
        (
            _ext(
                "EV-external-ports",
                [{"target": TARGET, "port": 3306, "service": "mysql", "state": "open"}],
            ),
            ("EXT-001", "high"),
        ),
        (
            _ext(
                "EV-external-ports",
                [{"target": TARGET, "port": 443, "service": "https", "state": "open"}],
            ),
            None,
        ),
        (_ext("EV-external-tls", [_tls(legacy={"TLSv1.1": "accepted"})]), ("EXT-002", "medium")),
        (_ext("EV-external-tls", [_tls()]), None),
        (
            _ext(
                "EV-external-tls",
                [_tls(verified=False, verify_error="certificate has expired", days_remaining=None)],
            ),
            ("EXT-003", "high"),
        ),
        (_ext("EV-external-tls", [_tls(days_remaining=3)]), ("EXT-003", "medium")),
    ],
)
def test_external_rules(evidence: Evidence, expected: tuple[str, str] | None) -> None:
    findings, failures = evaluate([evidence], FIXED_NOW)
    assert failures == []
    assert [(f.id, f.severity) for f in findings] == ([expected] if expected else [])


def test_run_external_metadata_and_reports(tmp_path: Path) -> None:
    config = parse_config(enabled_raw())
    audit = run_external(
        config, make_ctx(), FakeProber({3306}, addresses=["2001:db8::7"]), sleep=lambda _: None
    )
    # The default policy refuses documentation addresses, so nothing is probed.
    assert audit.collectors[0].status == "error"
    assert audit.run.external_checks is True and audit.run.profile == "external"

    path = tmp_path / "audit.yml"
    path.write_text(yaml.safe_dump(enabled_raw()))
    with pytest.raises(ConfigError):
        run_external(parse_config(base()), make_ctx(), FakeProber(set()))
    run_dir = external(path, tmp_path / "out", prober=FakeProber(set()), now=lambda: FIXED_NOW)
    assert (run_dir / "manifest.json").exists()


def test_cli_requires_confirmation(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["external", "--config", "unused.yml"]) == 2
    assert "--confirm-authorized" in capsys.readouterr().err
