from datetime import UTC, datetime

from plesk_audit.models import Evidence


def test_evidence_defaults_to_redacted() -> None:
    item = Evidence("EV-001", "system", "uname", datetime.now(UTC))
    assert item.redacted is True
