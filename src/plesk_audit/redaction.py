import re

_PATTERNS = (
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)",
            re.DOTALL,
        ),
        "[REDACTED PRIVATE KEY]",
    ),
    (
        re.compile(r"(?i)(password|passwd|token|secret|api[_-]?key)\s*[:=]\s*[^\s,;]+"),
        r"\1=[REDACTED]",
    ),
    (re.compile(r"(?i)(authorization:\s*)(basic|bearer)\s+\S+"), r"\1[REDACTED]"),
)


def redact_text(value: str) -> str:
    result = value
    for pattern, replacement in _PATTERNS:
        result = pattern.sub(replacement, result)
    return result
