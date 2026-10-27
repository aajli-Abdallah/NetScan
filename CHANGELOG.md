# Changelog (newest first)

## 1.0.5
- Login (Spring Security, form login + session). Everything is protected: page, API, live stream. CSRF protection with cookie token.
- Password: set `netscan.security.password` / env `NETSCAN_SECURITY_PASSWORD`, or a random one is generated on first start (logged once) and kept hashed in `data/admin.hash`.
- Export: backup JSON (with appVersion and format), devices CSV, events CSV (formula-injection safe, UTF-8 with BOM for Excel).
- Import with preview (new / updated / unchanged / removed / skipped), Merge or Replace. Merge rule: match by MAC, newest lastSeen wins, empty fields are filled. Old backups upgrade through an ordered hook; a file without appVersion is treated as 1.0.0.
- Automatic local backup: one file per day in `data/backups` (kept 14), written about 1 min after start if today's is missing.
- Radar page: Backup card (downloads, restore with preview), Test alert, Sign out.
- Tests: version compare, upgrade, CSV, merge rules, password hash, security and import round trip (MockMvc on in-memory H2).
- Final blueprint and README rewritten.

## 1.0.4
- Alerts for new unknown devices (JOINED + not known). First scan on an empty database is a baseline (no alerts).
- Live push with Server-Sent Events (/api/stream): scan finished and device changes. No polling needed (fallback every 60 s).
- Optional webhook (ntfy/text, Discord, Telegram, Slack), off by default. POST /api/alerts/test.
- Radar page: summary tiles, toasts, beep, desktop notifications, live indicator.
- No schema change (no migration). Alerts are derived from the events table.
- Tests: alert rules, webhook body formats, baseline and publish behaviour.

## 1.0.3
- Vendor lookup from MAC (OUI): small built-in seed + optional IEEE file `data/oui.csv` (overrides the seed). Randomized MACs are detected.
- Hostname via reverse DNS in parallel with a deadline (this computer uses its own name). Stored per device.
- Quick port scan on request: POST /api/saved/{id}/portscan, result stored (open_ports, ports_scanned_at).
- Migration V3: vendor, hostname, open_ports, ports_scanned_at.
- /api/saved and /api/devices now include vendor and hostname; /api/saved also openPorts.
- Radar page shows vendor, hostname, ports and a Scan ports button. API error messages are now returned.
- Tests: OUI parsing and lookup, port scanner (local socket), port list formatting.

## 1.0.2
- Scheduled scans every 5 min (configurable, can be switched off). A failed scan is logged and skipped.
- Online/offline detection with debounce (offline after 2 missed scans). Devices missing from a scan count as misses.
- History table `device_events` (JOINED, ONLINE, OFFLINE) with a snapshot of label, ip and known. Nightly purge (90 days).
- Migration V2: devices.online, devices.missed, device_events.
- Endpoints: GET /api/events, GET /api/status. /api/saved and /api/devices now include `online`.
- Radar page at `/` (static HTML + Canvas, no dependencies).
- Tests: change detection (offline, back online, joined, missing from scan).

## 1.0.1
- Persistence: H2 file database, Spring Data JPA, Flyway (V1__init.sql). Schema validated at start, never auto-changed.
- Devices remembered by MAC (UUID id): label, known flag, firstSeen, lastSeen, lastIp.
- Every scan syncs the database. New device = unknown; this computer = known. Offline devices keep their lastSeen.
- Endpoints: GET /api/saved, PATCH /api/saved/{id}, DELETE /api/saved/{id}. /api/devices now includes id, label, known, firstSeen, lastSeen.
- Tests: DeviceStore logic (Mockito), migration + repository (DataJpaTest).

## 1.0.0
- Subnet detection (skips Docker/VM adapters), scan range clamped to /24 minimum.
- Parallel ping/TCP sweep with virtual threads.
- ARP parsers: Linux (/proc/net/arp), Windows (arp -a), macOS (arp -an), OS auto-selected.
- Endpoints: /api/devices, /api/network, /api/info.
- Unit tests: CIDR math, 3 ARP parsers, MAC normalization.
- Docs folder created (BLUEPRINT, TESTING).
- No database yet (starts in 1.0.1).
