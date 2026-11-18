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

## Rules
| ID | Evidence | Severity | Condition |
|---|---|---|---|
| `SYS-001` | os-release | info | OS is not AlmaLinux 9.9 |
| `SYS-002` | time | low | NTP disabled or not synchronized |
| `NET-001-tcp-<port>` | listeners | medium / needs_review | MySQL/MariaDB, PostgreSQL, Redis, Elasticsearch, Memcached or MongoDB port on a wildcard address |
| `NET-002` | listeners | info | inventory of wildcard listeners |
