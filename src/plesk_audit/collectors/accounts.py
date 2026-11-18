"""Local accounts, privileged groups, sudo policy and SSH authorized_keys metadata.

Privileges: root for /etc/sudoers, /etc/sudoers.d and other users' authorized_keys;
otherwise ``partial``. Data: account name, UID/GID, home, shell (no GECOS); members of
privileged groups; sudo rule lines; per-file key counts, key types and option usage.
Never read: /etc/shadow, /etc/gshadow, private keys, key material or key comments.
"""

from __future__ import annotations

from typing import Any

from plesk_audit.collectors.base import Collection, CollectorContext
from plesk_audit.file_reader import is_allowed_file
from plesk_audit.models import CollectorResult

NAME = "accounts"
PRIVILEGED_GROUPS = ("adm", "root", "wheel")
NON_INTERACTIVE_SHELLS = frozenset(
    {
        "/sbin/nologin",
        "/usr/sbin/nologin",
        "/bin/false",
        "/usr/bin/false",
        "/bin/sync",
        "/sbin/shutdown",
        "/sbin/halt",
        "",
    }
)
_KEY_OPTIONS = ("command=", "from=", "restrict")
_MAX_KEY_FILES = 200


def parse_passwd(text: str) -> list[dict[str, Any]]:
    accounts: list[dict[str, Any]] = []
    for line in text.splitlines():
        # NIS compat entries (+/-) carry no local account data.
        if not line.strip() or line.startswith(("#", "+", "-")):
            continue
        fields = line.split(":")
        if len(fields) != 7 or not fields[2].isdigit() or not fields[3].isdigit():
            raise ValueError("unexpected passwd line")
        name, _pw, uid, gid, _gecos, home, shell = fields
        accounts.append(
            {
                "name": name,
                "uid": int(uid),
                "gid": int(gid),
                "home": home,
                "shell": shell,
                "interactive": shell not in NON_INTERACTIVE_SHELLS,
            }
        )
    if not accounts:
        raise ValueError("empty passwd")
    return sorted(accounts, key=lambda a: (a["uid"], a["name"]))


def parse_group(text: str) -> dict[str, list[str]]:
    groups: dict[str, list[str]] = {}
    for line in text.splitlines():
        fields = line.split(":")
        if len(fields) == 4 and fields[0] in PRIVILEGED_GROUPS:
            groups[fields[0]] = sorted(m for m in fields[3].split(",") if m)
    return dict(sorted(groups.items()))


def parse_uid_min(text: str) -> int:
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "UID_MIN" and parts[1].isdigit():
            return int(parts[1])
    return 1000


def parse_sudoers(text: str) -> dict[str, Any]:
    rules: list[dict[str, Any]] = []
    includes: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith(("#include", "@include")):
            includes.append(line)
            continue
        if not line or line.startswith(("#", "Defaults")):
            continue
        if line.split(None, 1)[0].endswith("_Alias"):
            continue
        upper = line.upper()
        rules.append(
            {
                "line": line,
                "nopasswd": "NOPASSWD:" in upper,
                "all_commands": upper.rstrip().endswith("ALL"),
            }
        )
    return {"rules": rules, "includes": includes}


def parse_authorized_keys(text: str) -> dict[str, Any]:
    key_types: dict[str, int] = {}
    restricted = 0
    count = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        tokens = line.split()
        type_index = next(
            (i for i, t in enumerate(tokens) if t.startswith(("ssh-", "ecdsa-", "sk-"))), None
        )
        if type_index is None:
            continue
        count += 1
        key_types[tokens[type_index]] = key_types.get(tokens[type_index], 0) + 1
        options = " ".join(tokens[:type_index])
        if any(opt in options for opt in _KEY_OPTIONS):
            restricted += 1
    return {
        "key_count": count,
        "key_types": dict(sorted(key_types.items())),
        "restricted_keys": restricted,
    }


def collect(ctx: CollectorContext) -> CollectorResult:
    c = Collection(NAME, ctx)

    accounts: list[dict[str, Any]] = []
    passwd = c.file("/etc/passwd")
    if passwd is not None:
        accounts = c.parse("/etc/passwd", parse_passwd, passwd.content) or []
    uid_min = 1000
    login_defs = c.file("/etc/login.defs", missing_ok=True)
    if login_defs is not None:
        uid_min = parse_uid_min(login_defs.content)
    if accounts:
        c.add(
            "local",
            "file:/etc/passwd",
            {
                "uid_min": uid_min,
                "accounts": accounts,
                "uid0": [a["name"] for a in accounts if a["uid"] == 0],
                "interactive_regular": [
                    a["name"] for a in accounts if a["interactive"] and a["uid"] >= uid_min
                ],
            },
        )

    group = c.file("/etc/group")
    if group is not None:
        c.add("privileged-groups", "file:/etc/group", {"groups": parse_group(group.content)})

    sudo_files: list[dict[str, Any]] = []
    paths = ["/etc/sudoers"]
    listing = c.directory("/etc/sudoers.d")
    if listing is not None:
        paths += [
            f"/etc/sudoers.d/{e.name}"
            for e in listing.entries
            if e.kind == "file" and is_allowed_file(f"/etc/sudoers.d/{e.name}")
        ]
    for path in paths:
        content = c.file(path)
        if content is not None:
            sudo_files.append({"path": path, **parse_sudoers(content.content)})
    if sudo_files:
        c.add("sudoers", "file:/etc/sudoers,/etc/sudoers.d/*", {"files": sudo_files})

    key_files: list[dict[str, Any]] = []
    candidates = [
        a for a in accounts if a["uid"] == 0 or (a["interactive"] and a["uid"] >= uid_min)
    ]
    skipped = 0
    for account in candidates[:_MAX_KEY_FILES]:
        path = f"{account['home'].rstrip('/')}/.ssh/authorized_keys"
        if not is_allowed_file(path):
            skipped += 1
            continue
        content = c.file(path, missing_ok=True)
        if content is not None:
            key_files.append(
                {"user": account["name"], "path": path, **parse_authorized_keys(content.content)}
            )
    if skipped:
        c.note(f"{skipped} home director(y/ies) outside the authorized_keys allow-list")
    if len(candidates) > _MAX_KEY_FILES:
        c.note(f"authorized_keys checked for first {_MAX_KEY_FILES} accounts only")
    if accounts:
        c.add("authorized-keys", "file:~/.ssh/authorized_keys", {"files": key_files})
    return c.result()
