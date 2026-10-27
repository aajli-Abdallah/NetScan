# NetScan Blueprint (project memory, final for 1.0.5)
Read this first in any new session. Update it on every version.

## 1. Goal and scope
Home network scanner and intruder alert for one person. Offline, no cloud account. Learning and portfolio project.
Out of scope so far: multiple users, bandwidth per device, IPv6, several subnets, mobile app.

## 2. Working rules (owner preferences)
- Free plan: concise replies, targeted patches (scripted, assert each target appears once), rewrite a file only when many places change.
- The assistant cannot compile or run Java. The owner builds and tests. Always say "I haven't compiled this". Fix reported errors with the smallest change.
- Ambiguity: state the assumption and proceed; at most one question, only if it changes what gets built.
- Check what already exists before building; renumber the plan if needed.
- Each version = `NetScan-v<version>.zip`. Corrections: 1.0.5 -> 1.0.5.1.
- Every version updates together: pom version, README title, CHANGELOG (newest first), zip name, this file, docs/TESTING.md.
- Version is read from build-info (BuildProperties), never hard-coded.
- Data rules: Flyway migration for every schema change, `ddl-auto=validate`, never auto-update. UUID string ids. Backups carry appVersion and format. Old backups must stay importable. Import has a preview and Merge/Replace. Decide merge rules before import code.
- End each delivery with a short manual test list, next steps, and at most one open decision.

## 3. Version history
| Version | Delivered |
|---|---|
| 1.0.0 | Subnet detection, ping sweep, ARP parsers (Linux/Windows/macOS), device endpoint, tests |
| 1.0.1 | H2 + JPA + Flyway, devices by MAC, labels, known flag, first/last seen |
| 1.0.2 | Scheduled scans (5 min), online/offline with debounce, event history, radar page |
| 1.0.3 | Vendor (OUI), hostname (reverse DNS), on-demand port scan |
| 1.0.4 | Alerts for new unknown devices, SSE live push, optional webhook, page polish |
| 1.0.5 | Login + CSRF, JSON/CSV export, import with preview, daily local backups, final docs |

## 4. Architecture
```
web/        DeviceController (/api/devices, /network, /info)   SavedDeviceController (/api/saved)
            HistoryController (/events, /status)  AlertController (/stream, /alerts/test)  ExportController (/export, /import)
scan/       ScanService (sync, cached 10 s) -> NetworkDetector, PingSweeper, ArpReader(arp/), HostnameResolver
            ScanScheduler (scan every 5 min, nightly event purge)   PortScanner (on request only)
store/      DeviceStore (@Transactional: sync, change detection, update, delete, ports, events) , repositories, entities
alert/      EventHub (SSE), AlertService (after-commit listener), WebhookNotifier
backup/     BackupService (export, preview/apply, daily file), BackupUpgrader, Versions, CsvWriter, BackupScheduler
security/   SecurityConfig (form login, cookie CSRF, password hash file)
net/        Cidr, MacUtil, OuiLookup (pure logic, unit tested)
model/      records: Device, DeviceView, SavedDevice, DeviceEvent, DeviceChanged, OpenPort, NetworkInfo, ScanResult...
static/index.html   radar page (plain JS + Canvas, textContent only)
```
Scan flow: detect interface -> sweep range (>= /24) -> read ARP -> merge -> resolve hostnames -> DeviceStore.sync (vendor, events, publish) -> EventHub "scan".

## 5. Database (Flyway)
- V1 `devices`: id (UUID), mac (unique, identity), label, known, last_ip, first_seen, last_seen.
- V2: `devices.online`, `devices.missed`; table `device_events` (device_id, mac, label, ip, known, type, occurred_at). Snapshot columns, no foreign key, so history survives "forget".
- V3: `devices.vendor`, `hostname`, `open_ports` (csv), `ports_scanned_at`.
- Next migration is V4. H2 file `./data/netscan`. SQL is kept portable for PostgreSQL.

## 6. API (all need login; POST/PATCH/DELETE need the CSRF header, the page does this)
| Endpoint | Purpose |
|---|---|
| GET /api/devices[?refresh=true] | scan result (cached 10 s) |
| GET /api/network, /api/info, /api/status | interface, version, last scan |
| GET /api/saved[?known=] | remembered devices |
| PATCH /api/saved/{id} | label, known |
| DELETE /api/saved/{id} | forget |
| POST /api/saved/{id}/portscan | quick TCP scan (online devices only) |
| GET /api/events[?deviceId=&limit=] | history |
| GET /api/stream | Server-Sent Events: `scan`, `device` |
| POST /api/alerts/test | fake alert to page and webhook |
| GET /api/export/backup.json, devices.csv, events.csv | downloads |
| POST /api/import/preview, /api/import (?mode=merge or replace) | restore |

## 7. Configuration (application.properties; env vars use NETSCAN_ prefix, upper case)
| Key | Default |
|---|---|
| server.address / server.port | 127.0.0.1 / 8080 |
| netscan.scan-interval, scan-initial-delay | PT5M, PT20S |
| netscan.scheduler.enabled | true |
| netscan.offline-after-misses | 2 |
| netscan.events-retention-days | 90 |
| netscan.timeout-ms, probe-ports | 300, 80,443,22,53,445 |
| netscan.hostname-timeout-ms | 2000 |
| netscan.quick-ports, portscan-timeout-ms | 16 common ports, 500 |
| netscan.oui-file | ./data/oui.csv (optional IEEE list) |
| netscan.alert.webhook-url, webhook-format | empty (off), text |
| netscan.security.username, password, hash-file | admin, empty (generated), ./data/admin.hash |
| netscan.backup.enabled, dir, keep | true, ./data/backups, 14 |

## 8. Key decisions
- Identity = MAC. ARP table instead of raw sockets (no admin rights). A refused TCP connection counts as alive.
- Offline needs 2 missed scans; devices absent from a scan count as misses; a failed scan changes nothing.
- reachable (this scan) vs online (debounced). lastSeen moves only when reachable.
- Alerts only for new unknown MACs (JOINED, not known). First scan on an empty DB is a baseline.
- Events are not in the backup (history); CSV export exists. Backup = devices.
- Merge rule: match by MAC, newest lastSeen wins, empty fields filled, firstSeen earliest, lastSeen latest. No updatedAt column, so "newest" is approximate.
- Vendor list: small verified seed plus a one-time IEEE download. No data typed from memory beyond the seed.
- Port scan on request only, only for IPs NetScan recorded.
- Security: form login, session, cookie CSRF, password hashed on disk, localhost only. Webhook secrets in env vars.
- Event type stored as a plain string (Hibernate enum validation on H2), timestamps as Instant (UTC).

## 9. Known limits and pitfalls
- Random (private) MACs: phones may appear as new unknown devices after rejoining. Labels matter more than vendors.
- Guest-isolated Wi-Fi hides devices. IPv4 only. One interface (first private one). Sweep is at least /24.
- Docker on Windows/Mac cannot see the LAN. A locked-down device can look offline.
- Reverse DNS often empty on home routers.
- Plain HTTP: do not expose beyond localhost without HTTPS. No login throttling yet.
- Generated password changes only if `data/admin.hash` is deleted.

## 10. Ideas for later
PostgreSQL profile; HTTPS/reverse proxy guide; login throttling; mDNS/NetBIOS names; merging a phone's several random MACs; uptime per day from events; per-device page; i18n of UI text; Raspberry Pi 24/7 agent; router DHCP/SNMP for bandwidth; unknown-device-comes-back alerts (optional); updatedAt column for exact merge.

## 11. Quality checklist (per version)
Changelog written, version bumped everywhere, migration added and `mvn test` green (the DataJpaTest and SecurityAndImportTest validate the schema and wiring), old backups still import, empty/invalid input handled, manual test list updated.
