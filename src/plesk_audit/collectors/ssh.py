"""Effective OpenSSH server configuration via ``sshd -T``.

Privileges: root (sshd loads host keys to validate the configuration); otherwise
``error``. Data: a fixed set of security-relevant directives only. Host keys and other
directives are not stored. No connections are made.
"""

from __future__ import annotations

from typing import Any

from plesk_audit.collectors.base import Collection, CollectorContext
from plesk_audit.models import CollectorResult

NAME = "ssh"
SINGLE_KEYS = frozenset(
    {
        "permitrootlogin",
        "passwordauthentication",
        "kbdinteractiveauthentication",
        "challengeresponseauthentication",
        "permitemptypasswords",
        "pubkeyauthentication",
        "gssapiauthentication",
        "usepam",
        "x11forwarding",
        "allowtcpforwarding",
        "allowagentforwarding",
        "permituserenvironment",
        "maxauthtries",
        "logingracetime",
        "clientaliveinterval",
        "loglevel",
        "authorizedkeysfile",
    }
)
LIST_KEYS = frozenset(
    {"ciphers", "macs", "kexalgorithms", "hostkeyalgorithms", "pubkeyacceptedalgorithms"}
)
MULTI_KEYS = frozenset(
    {"port", "listenaddress", "allowusers", "allowgroups", "denyusers", "denygroups"}
)


def parse_sshd_t(text: str) -> dict[str, Any]:
    config: dict[str, Any] = {}
    for line in text.splitlines():
        key, _, value = line.strip().partition(" ")
        key = key.lower()
        value = value.strip()
        if key in SINGLE_KEYS:
            config[key] = value
        elif key in LIST_KEYS:
            config[key] = [v for v in value.split(",") if v]
        elif key in MULTI_KEYS:
            config.setdefault(key, []).extend(value.split())
    if "permitrootlogin" not in config:
        raise ValueError("not sshd -T output")
    return dict(sorted(config.items()))


def collect(ctx: CollectorContext) -> CollectorResult:
    c = Collection(NAME, ctx)
    result = c.command("sshd_effective")
    if result is not None:
        config = c.parse("sshd_effective", parse_sshd_t, result.stdout)
        if config is not None:
            c.add("effective-config", "command:sshd -T", config)
    return c.result()
