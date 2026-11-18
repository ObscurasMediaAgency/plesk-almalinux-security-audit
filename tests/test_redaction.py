from plesk_audit.redaction import redact_text


def test_redacts_password_assignment() -> None:
    assert "hunter2" not in redact_text("password=hunter2")


def test_redacts_bearer_authorization() -> None:
    assert "abc123" not in redact_text("Authorization: Bearer abc123")


def test_redacts_private_key_block_including_unterminated() -> None:
    body = "MIIsyntheticNOTAREALKEY"
    block = f"-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----"
    assert body not in redact_text(f"before\n{block}\nafter")
    assert body not in redact_text(f"-----BEGIN RSA PRIVATE KEY-----\n{body}")
