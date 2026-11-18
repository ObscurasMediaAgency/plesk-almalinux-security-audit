# Collectors

Implemented collectors, their sources, required privileges and collected data. Collectors not listed here are reported as `skipped` (`not implemented yet`).

## `system`
| Evidence ID | Source | Data |
|---|---|---|
| `EV-system-os-release` | `/etc/os-release` | `ID`, `ID_LIKE`, `NAME`, `PLATFORM_ID`, `PRETTY_NAME`, `VERSION_ID` |
| `EV-system-hostname` | `/proc/sys/kernel/hostname` | hostname |
| `EV-system-uptime` | `/proc/uptime` | uptime in seconds |
| `EV-system-kernel` | `uname -s -r -m` | kernel name, release, machine |
| `EV-system-time` | `timedatectl show --property=Timezone --property=NTP --property=NTPSynchronized` | timezone, NTP enabled/synchronized |
| `EV-system-plesk-version` | `/usr/local/psa/version` | first line and version; `installed: false` if absent |

- Privileges: none.
- Status: `partial` if some sources fail, `error` if all fail.
- **VERIFY:** location and format of the Plesk version file on Obsidian 18.0.82.31 (assumed `18.0.82 <OS> <build>`). Prefer a documented Plesk CLI once confirmed.

## `network`
| Evidence ID | Source | Data |
|---|---|---|
| `EV-network-listeners` | `ss -H -t -u -l -n -p` | protocol, state, local address, interface, port, bind scope (`wildcard`/`loopback`/`specific`), process names and PIDs |

- Privileges: root required for process attribution of other users' sockets; otherwise `partial`.
- Limitations: bind scope is not exposure. Firewalld/Plesk Firewall are not yet evaluated. No traffic is generated.

## `packages`
| Evidence ID | Source | Data |
|---|---|---|
| `EV-packages-installed` | `rpm -qa --qf <NAME EPOCH VERSION RELEASE ARCH INSTALLTIME>` | package NEVRA and install time; installed `kernel-core` releases, newest install first |
| `EV-packages-security-updates` | `dnf -q -C updateinfo list --security --available` | advisory ID, severity, package; counts per severity |

- Privileges: none; the dnf cache must be readable.
- Network: none. `-C` uses cached repository metadata only, so results are only as fresh as the last `dnf makecache`. dnf may write to its own log files.
- **VERIFY:** `dnf updateinfo` output format and `-C` behaviour on AlmaLinux 9.9 (expected `<advisory> <Severity>/Sec. <nevra>`). Unrecognised lines are counted and reported as `partial`.

## `services`
| Evidence ID | Source | Data |
|---|---|---|
| `EV-services-units` | `systemctl list-units --type=service,timer --all ...` and `systemctl list-unit-files --type=service,timer ...` | unit, type, load/active/sub state, unit-file state; failed units; enabled count |

- Privileges: none. Unit descriptions are not collected.

## `accounts`
| Evidence ID | Source | Data |
|---|---|---|
| `EV-accounts-local` | `/etc/passwd`, `/etc/login.defs` | name, UID, GID, home, shell, interactive flag (no GECOS); UID 0 accounts; interactive regular accounts |
| `EV-accounts-privileged-groups` | `/etc/group` | members of `adm`, `root`, `wheel` |
| `EV-accounts-sudoers` | `/etc/sudoers`, `/etc/sudoers.d/<name>` | rule lines (no `Defaults`/aliases), NOPASSWD and ALL flags, include directives |
| `EV-accounts-authorized-keys` | `~/.ssh/authorized_keys` of UID 0 and interactive regular accounts | key count, key types, number of keys restricted by `from=`/`command=`/`restrict` |

- Privileges: root for sudoers and other users' `authorized_keys`; otherwise `partial`.
- Never read: `/etc/shadow`, `/etc/gshadow`, private keys, key material or key comments.
- `authorized_keys` is only read below `/root`, `/home/<user>` and `/var/www/vhosts/<domain>`; other homes are counted and noted. Sudoers include files with dots or `~` in their name are ignored (as sudo does).

## Rules
| ID | Evidence | Severity | Condition |
|---|---|---|---|
| `SYS-001` | os-release | info | OS is not AlmaLinux 9.9 |
| `SYS-002` | time | low | NTP disabled or not synchronized |
| `NET-001-tcp-<port>` | listeners | medium / needs_review | MySQL/MariaDB, PostgreSQL, Redis, Elasticsearch, Memcached or MongoDB port on a wildcard address |
| `NET-002` | listeners | info | inventory of wildcard listeners |
| `PKG-001` | security-updates | medium if Critical/Important, else low | security advisories pending (cached metadata) |
| `PKG-002` | installed + kernel | low | running kernel is not the most recently installed `kernel-core` |
| `SVC-001` | units | low | failed systemd units |
| `ACC-001` | local | high / needs_review | accounts other than `root` with UID 0 |
| `ACC-002` | sudoers | medium / needs_review | NOPASSWD sudo rules |
| `ACC-003` | authorized-keys | info / needs_review | SSH keys authorized for root |
