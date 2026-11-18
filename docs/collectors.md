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
- Limitations: bind scope is not exposure. `NET-001` combines it with firewalld evidence (see `security_controls`); direct nftables/iptables rules and upstream firewalls are not evaluated. No traffic is generated.

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

## `ssh`
| Evidence ID | Source | Data |
|---|---|---|
| `EV-ssh-effective-config` | `sshd -T` | fixed allow-list of directives: root login, password/keyboard-interactive/empty-password/pubkey/GSSAPI auth, PAM, forwarding, `MaxAuthTries`, `LoginGraceTime`, `ClientAliveInterval`, `LogLevel`, `AuthorizedKeysFile`, ports, listen addresses, Allow/Deny users/groups, ciphers, MACs, KEX, host key and pubkey algorithms |

- Privileges: root (sshd loads host keys to validate the configuration); otherwise `error`. Host key paths and all other directives are discarded.
- Limitation: `Match` blocks are not evaluated (`sshd -T` without `-C` shows global settings).
- **VERIFY:** `sshd -T` behaviour and value spelling (`without-password` vs. `prohibit-password`) on the installed OpenSSH build.

## `security_controls`
| Evidence ID | Source | Data |
|---|---|---|
| `EV-security_controls-selinux` | `getenforce`, `/etc/selinux/config` | runtime mode, configured mode and type |
| `EV-security_controls-firewalld` | `firewall-cmd --state`, `--get-default-zone`, `--list-all-zones` | running flag, default zone, per zone: active/default, target, interfaces, sources, services, ports, protocols, source ports, rich rules |
| `EV-security_controls-fail2ban` | `fail2ban-client status` | installed flag, jail names (no banned IPs) |

- Privileges: none for SELinux and the firewalld state; root for zone details (polkit) and the Fail2Ban socket, otherwise `partial`.
- `firewall-cmd --state` exit code 252 is recorded as "not running"; a missing `fail2ban-client` as "not installed".
- **VERIFY:** firewalld zone header format (`public (active)` / `(default, active)`), exit code 252 and `fail2ban-client status` output on the installed build. Plesk Firewall on EL9 is assumed to apply its rules via firewalld.

## `plesk`
| Evidence ID | Source | Data |
|---|---|---|
| `EV-plesk-version` | `plesk version` | installed flag, product string, version, OS version, build date, revision |
| `EV-plesk-extensions` | `plesk bin extension --list` | extension ID, name, version; count |

- Privileges: root; otherwise `error`. A missing `plesk` binary is recorded as `installed: false`.
- Never used: `plesk installer` (network access), `plesk db` (database contents), password/admin utilities.
- **VERIFY:** output format of both commands on Obsidian 18.0.82.31 (assumed `Key: value` lines and `id - name - version` lines). Unrecognised extension lines are counted and reported as `partial`.

## `persistence` (profile `triage`)
| Evidence ID | Source | Data |
|---|---|---|
| `EV-persistence-cron` | `/etc/cron.d`, `/etc/cron.{hourly,daily,weekly,monthly}`, `/var/spool/cron` | per entry: name, type, mode, UID/GID, size, mtime |
| `EV-persistence-systemd` | `/etc/systemd/system` | same metadata (top level only) |
| `EV-persistence-profile` | `/etc/profile.d` | same metadata |
| `EV-persistence-ld-preload` | `/etc/ld.so.preload` | present flag, preloaded library paths |

- Privileges: root for `/var/spool/cron`; otherwise `partial`.
- Metadata only: no recursion, symlinked directories are refused, at most 1000 entries per directory. Crontab and unit file contents are not read because they may embed credentials.

## `logs` (profile `triage` and `logs.enabled: true`)
| Evidence ID | Source | Data |
|---|---|---|
| `EV-logs-sources` | configured `logs.sources` | lookback window, per source: lines considered/in window/without timestamp, read limit hit, earliest timestamp, window coverage |
| `EV-logs-ssh-auth` | `/var/log/secure` patterns | failed SSH attempts total and top 20 per IP and per existing account, invalid-user attempt count, accepted logins aggregated by user/IP/method with first/last time (max. 100) |
| `EV-logs-sudo` | `/var/log/secure` patterns | sudo invocations per invoking user (top 20) |
| `EV-logs-mail-auth` | `/var/log/maillog` patterns | failed Postfix SASL / Dovecot logins total and top 20 per IP |

- Allowed sources: `/var/log/secure`, `/var/log/messages`, `/var/log/maillog` only (enforced by config validation and the file allow-list). Rotated files are not read.
- Bounds: the last `runtime.max_file_bytes` of each file, then the last `logs.max_lines_per_source` lines, filtered to `logs.lookback_hours`. If the read limit is reached before the window start, the collector reports `partial`.
- Never stored: message bodies, sudo commands, usernames from invalid-user attempts (often mistyped passwords), mailbox names, key fingerprints.
- Timestamps: classic syslog timestamps are interpreted in the host's local timezone with year inference; RFC 3339 timestamps are also accepted.
- **VERIFY:** rsyslog timestamp format and the sshd/sudo/Postfix/Dovecot message formats on the installed build.

## `external` (separate `plesk-audit external` command)
Not a local collector: it runs only via `plesk-audit external --config … --confirm-authorized` and never as part of `collect`.

| Evidence ID | Source | Data |
|---|---|---|
| `EV-external-scope` | configuration | probed targets with resolved addresses, port list, timeout, probe interval, probe count |
| `EV-external-ports` | TCP connect | per target and port: service label and state (`open`, `closed`, `filtered`, `error`) |
| `EV-external-tls` | TLS handshake (`tls_test_enabled`) | per open implicit-TLS port (443, 465, 993, 995, 8443): certificate verification result/error, negotiated protocol, expiry and days remaining, TLS 1.0/1.1 acceptance (`accepted`, `rejected`, `client_unsupported`, `error`) |

- Opt-in: `audit.external_checks: true` plus 1–5 entries in `external.allowed_targets`, each a public (global) IP address or a fully qualified hostname. CIDR ranges, wildcards, URLs, ports, private/loopback/documentation addresses and duplicates are rejected. `external.nmap_enabled` must stay `false`.
- Hostnames are resolved once; only the first public address is probed, non-public resolved addresses are skipped.
- Fixed port list in code: 21, 22, 25, 80, 106, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 6379, 8443, 8880, 11211. Probes are sequential with a 0.5 s pause and a timeout of `min(runtime.command_timeout_seconds, 5)` s. No payloads, banners, logins or STARTTLS negotiation.
- Legacy TLS tests need a client OpenSSL that still allows TLS 1.0/1.1 at `SECLEVEL=0`; otherwise the result is `client_unsupported` (not evidence of a secure server).

## Rules
| ID | Evidence | Severity | Condition |
|---|---|---|---|
| `SYS-001` | os-release | info | OS is not AlmaLinux 9.9 |
| `SYS-002` | time | low | NTP disabled or not synchronized |
| `NET-001-tcp-<port>` | listeners + firewalld | high if firewalld is not running or an interface-bound zone allows the port (port, firewalld service or target ACCEPT); medium if only source-bound zones/rich rules allow it or firewall state is unknown; low if filtered | MySQL/MariaDB, PostgreSQL, Redis, Elasticsearch, Memcached or MongoDB port on a wildcard address |
| `NET-002` | listeners | info | inventory of wildcard listeners |
| `PKG-001` | security-updates | medium if Critical/Important, else low | security advisories pending (cached metadata) |
| `PKG-002` | installed + kernel | low | running kernel is not the most recently installed `kernel-core` |
| `SVC-001` | units | low | failed systemd units |
| `ACC-001` | local | high / needs_review | accounts other than `root` with UID 0 |
| `ACC-002` | sudoers | medium / needs_review | NOPASSWD sudo rules |
| `ACC-003` | authorized-keys | info / needs_review | SSH keys authorized for root |
| `SSH-001` | ssh | medium | `PermitRootLogin yes` |
| `SSH-002` | ssh | low | password or PAM keyboard-interactive authentication enabled |
| `SSH-003` | ssh | high | `PermitEmptyPasswords yes` |
| `SSH-004` | ssh | low | CBC/3DES/arcfour/blowfish ciphers, MD5/96-bit/umac-64 MACs or SHA-1 DH key exchange (hmac-sha1 is tolerated: EL9 DEFAULT policy) |
| `FW-001` | firewalld | medium / needs_review | firewalld not running |
| `FW-002` | firewalld | medium | default or interface-bound active zone with target ACCEPT |
| `SEC-001` | selinux | medium if disabled, low if permissive or not enforcing after reboot | SELinux not enforcing |
| `SEC-002` | units + fail2ban | medium if `fail2ban.service` is inactive/absent, low if no jail name contains `ssh` | Fail2Ban not protecting SSH |
| `SEC-003` | units | low | `auditd.service` inactive or absent |
| `PLK-001` | plesk version (CLI, else version file) | info / needs_review | Plesk not installed or release differs from 18.0.82 |
| `LOG-001` | ssh-auth | medium / needs_review | accepted root login via password or keyboard-interactive |
| `LOG-002` | ssh-auth | low | ≥ 100 failed/invalid SSH attempts or ≥ 20 from one IP in the window |
| `LOG-003` | ssh-auth | medium / needs_review, low confidence | accepted login from an IP with ≥ 5 failures in the window |
| `LOG-004` | mail-auth | low | ≥ 100 failed mail logins in the window |
| `PER-001` | ld-preload | high / needs_review | `/etc/ld.so.preload` lists libraries |
| `PER-002` | cron/systemd/profile | info / needs_review, low confidence | files or symlinks modified in the last 7 days |
| `PER-003` | cron/systemd/profile | medium / needs_review | world-writable entries, or non-root owned entries outside `/var/spool/cron` |
| `EXT-001` | external ports | high | MySQL, PostgreSQL, Redis, Memcached or poppassd reachable from the auditor |
| `EXT-002` | external tls | medium | TLS 1.0 or 1.1 handshake accepted |
| `EXT-003` | external tls | high if certificate verification fails, medium if it expires in < 14 days | certificate invalid or expiring |
