# NetScan v1.0.5

> **Home network scanner and intruder-alert system.**
> Detects every device on your LAN, remembers them, watches for changes, and alerts you when an unknown device joins.

[![Java](https://img.shields.io/badge/Java-21-orange)](#requirements)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.3-green)](#tech-stack)
[![License](https://img.shields.io/badge/License-MIT-blue)](LICENSE)

---

## Author

| | |
|---|---|
| **Name** | AAJLI Abdallah |
| **Email** | [ingenieur.aajli@gmail.com](mailto:ingenieur.aajli@gmail.com) |
| **GitHub** | [github.com/aajli-Abdallah](https://github.com/aajli-Abdallah) |
| **Website** | [aajli.com](https://aajli.com) |

---

## Features

- **Radar dashboard** — devices displayed as dots on an animated radar canvas (green = known, red pulsing = unknown, grey = offline, cyan = this computer). Click a dot to label, mark known, scan ports, or forget.
- **Automatic scanning** — scans your network every 5 minutes (configurable). A device is marked offline after 2 missed scans.
- **Intruder alerts** — instant alerts for new unknown MAC addresses via the page (toast + beep + desktop notification), server log, and optional phone push (ntfy, Discord, Telegram, Slack).
- **Live updates** — Server-Sent Events push scan results and device changes to the browser in real time, no polling needed.
- **Device history** — tracks JOINED / ONLINE / OFFLINE events (kept 90 days).
- **Vendor & hostname** — MAC vendor lookup (OUI), reverse DNS hostnames.
- **On-demand port scan** — quick TCP scan of 16 common ports on any online device.
- **Backup & restore** — JSON backup (with version and format metadata), CSV exports (devices + events), restore with preview (Merge or Replace mode), automatic daily backups.
- **Security** — form login with session, cookie CSRF protection, password hashed on disk, localhost-only by default.
- **Fully offline** — no cloud, no account, no tracking. One user, one machine.

---

## Tech Stack

| Component | Technology |
|---|---|
| Language | Java 21 (virtual threads) |
| Framework | Spring Boot 3.3.5 |
| Security | Spring Security (form login, session, CSRF) |
| Database | H2 (file-based) |
| Migrations | Flyway (V1 → V3) |
| ORM | Spring Data JPA (Hibernate, `ddl-auto=validate`) |
| Build | Maven |
| Frontend | Plain HTML + JavaScript + Canvas (no dependencies) |

---

## Requirements

- **Java 21** or later
- **Maven 3.8+**
- A direct connection to your LAN (not inside Docker — a container cannot see your network)

---

## Quick Start

```bash
# Build and run tests
mvn test

# Start the application
mvn spring-boot:run
```

Open [http://localhost:8080/](http://localhost:8080/) and sign in.

> **Important:** Run NetScan directly on your machine, not in Docker. Only scan networks you own or have permission to scan.

---

## Login & Authentication

| Setting | Details |
|---|---|
| Default username | `admin` (configurable via `netscan.security.username`) |
| First start | A random password is logged once (`FIRST RUN - ...`) and stored hashed in `data/admin.hash`. Delete that file to generate a new one. |
| Custom password | Set the environment variable `NETSCAN_SECURITY_PASSWORD`. Never commit passwords. |
| Binding | Server listens on `127.0.0.1` only. If you expose it to your LAN (`server.address`), put HTTPS in front first. |

---

## Architecture

```
NetScanApplication.java          Spring Boot entry point

web/        DeviceController       /api/devices, /api/network, /api/info
            SavedDeviceController  /api/saved (CRUD + port scan)
            HistoryController      /api/events, /api/status
            AlertController        /api/stream (SSE), /api/alerts/test
            ExportController       /api/export, /api/import

scan/       ScanService            sync scan, cached 10 s
            ScanScheduler          every 5 min + nightly event purge
            NetworkDetector        subnet & interface detection
            PingSweeper            parallel ping/TCP sweep (virtual threads)
            HostnameResolver       reverse DNS
            PortScanner            on-demand TCP scan

store/      DeviceStore            @Transactional: sync, change detection, events
            DeviceEntity           JPA entity (devices table)
            DeviceEventEntity      JPA entity (device_events table)
            DeviceRepository       Spring Data repository
            DeviceEventRepository  Spring Data repository

alert/      AlertService           after-commit listener for new unknowns
            EventHub               SSE broadcaster
            WebhookNotifier        POST to ntfy/Discord/Telegram/Slack

backup/     BackupService          export, preview/apply, daily file
            BackupUpgrader         upgrades old backup formats
            BackupScheduler        daily local backup
            CsvWriter              CSV export (Excel-safe)
            Versions               semver compare

security/   SecurityConfig         form login, cookie CSRF, password hash

net/        Cidr                   CIDR math
            MacUtil                MAC normalization
            OuiLookup              vendor lookup from MAC

model/      Device, DeviceView, SavedDevice, DeviceEvent,
            DeviceChanged, OpenPort, NetworkInfo, ScanResult,
            UpdateRequest, EventType   (records / enums)

resources/
  static/index.html               radar page (plain JS + Canvas)
  db/migration/                    Flyway SQL (V1, V2, V3)
  application.properties           configuration defaults
```

**Scan flow:** detect interface → sweep range (≥ /24) → read ARP table → merge → resolve hostnames → `DeviceStore.sync` (vendor, events, publish) → `EventHub` SSE broadcast.

---

## API Reference

All endpoints require login. POST / PATCH / DELETE require the `X-XSRF-TOKEN` header (the page handles this automatically).

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/devices[?refresh=true]` | Scan result (cached 10 s) |
| GET | `/api/network` | Network interface info |
| GET | `/api/info` | App version, author, OS, Java |
| GET | `/api/status` | Last scan time, scheduler state |
| GET | `/api/saved[?known=]` | Remembered devices |
| PATCH | `/api/saved/{id}` | Update label, known flag |
| DELETE | `/api/saved/{id}` | Forget a device |
| POST | `/api/saved/{id}/portscan` | Quick TCP scan (online only) |
| GET | `/api/events[?deviceId=&limit=]` | Event history |
| GET | `/api/stream` | SSE: `scan`, `device` events |
| POST | `/api/alerts/test` | Send a fake alert (page + webhook) |
| GET | `/api/export/backup.json` | Download JSON backup |
| GET | `/api/export/devices.csv` | Download devices CSV |
| GET | `/api/export/events.csv` | Download events CSV |
| POST | `/api/import/preview?mode=` | Preview a restore (merge / replace) |
| POST | `/api/import?mode=` | Apply a restore |

---

## Configuration

All properties can be set in `application.properties` or as environment variables (prefix `NETSCAN_`, uppercase, underscores).

| Property | Default | Description |
|---|---|---|
| `server.address` | `127.0.0.1` | Bind address |
| `server.port` | `8080` | HTTP port |
| `netscan.scan-interval` | `PT5M` | Time between automatic scans |
| `netscan.scan-initial-delay` | `PT20S` | Delay before the first scan |
| `netscan.scheduler.enabled` | `true` | Enable/disable auto scanning |
| `netscan.offline-after-misses` | `2` | Missed scans before marking offline |
| `netscan.events-retention-days` | `90` | Days to keep event history |
| `netscan.timeout-ms` | `300` | Ping/TCP probe timeout (ms) |
| `netscan.probe-ports` | `80,443,22,53,445` | Ports used during sweep probes |
| `netscan.hostname-timeout-ms` | `2000` | Reverse DNS lookup timeout |
| `netscan.quick-ports` | 16 common ports | Ports for on-demand scan |
| `netscan.portscan-timeout-ms` | `500` | Per-port timeout for on-demand scan |
| `netscan.oui-file` | `./data/oui.csv` | Path to IEEE OUI vendor list |
| `netscan.alert.webhook-url` | *(empty — off)* | Webhook URL for push alerts |
| `netscan.alert.webhook-format` | `text` | `text`, `discord`, `telegram`, or `slack` |
| `netscan.security.username` | `admin` | Login username |
| `netscan.security.password` | *(auto-generated)* | Login password (env: `NETSCAN_SECURITY_PASSWORD`) |
| `netscan.security.hash-file` | `./data/admin.hash` | Hashed password file |
| `netscan.backup.enabled` | `true` | Enable daily local backups |
| `netscan.backup.dir` | `./data/backups` | Backup directory |
| `netscan.backup.keep` | `14` | Number of daily backups to retain |

---

## Database

- **Engine:** H2 file database in `./data/netscan`
- **Migrations:** Flyway (V1 → V3), SQL kept portable for PostgreSQL
- **Schema validation:** `ddl-auto=validate` — Hibernate never modifies the schema
- **Identity:** UUID string IDs, MAC as the unique device identity

| Migration | Changes |
|---|---|
| V1 | `devices` table: id, mac, label, known, last_ip, first_seen, last_seen |
| V2 | `devices.online`, `devices.missed`; `device_events` table |
| V3 | `devices.vendor`, `hostname`, `open_ports`, `ports_scanned_at` |

---

## Optional Setup

### Full vendor list (OUI)

```bash
mkdir data
curl -L -o data/oui.csv https://standards-oui.ieee.org/oui/oui.csv
```

Restart the app. If the download is blocked, save the file manually from a browser.

### Phone push notifications

Set the webhook URL and format:

```properties
netscan.alert.webhook-url=https://ntfy.sh/your-secret-topic
netscan.alert.webhook-format=text
```

Supported formats: `text` (ntfy), `discord`, `telegram`, `slack`. Use the **Test alert** button in the UI to verify.

---

## Data & Backup

- All data lives in `./data/` (database, hash file, backups).
- A daily JSON backup is written to `data/backups/` (~1 min after start), keeping the last 14 copies.
- **Export:** JSON backup (with `appVersion` and format metadata), devices CSV, events CSV.
- **Import:** upload a JSON backup → Preview (shows new / updated / unchanged / removed / skipped) → Apply with **Merge** or **Replace** mode.
  - **Merge:** match by MAC, newest `lastSeen` wins, empty fields filled, `firstSeen` earliest.
  - **Replace:** wipe current data and import everything.
- Old backups (even without `appVersion`) are automatically upgraded through versioned hooks.

---

## Version History

| Version | Highlights |
|---|---|
| **1.0.5** | Login + CSRF, JSON/CSV export, import with preview, daily local backups, final docs |
| **1.0.4** | Alerts for new unknowns, SSE live push, optional webhook (ntfy/Discord/Telegram/Slack), tiles & toasts |
| **1.0.3** | Vendor (OUI), hostname (reverse DNS), on-demand port scan |
| **1.0.2** | Scheduled scans, online/offline detection with debounce, event history, radar page |
| **1.0.1** | H2 + JPA + Flyway persistence, devices by MAC, labels, known flag |
| **1.0.0** | Subnet detection, ping/TCP sweep, ARP parsers (Linux/Windows/macOS), initial API |

See [CHANGELOG.md](CHANGELOG.md) for full details.

---

## Known Limitations

- **Random MACs:** phones may appear as new unknown devices after rejoining Wi-Fi (private/randomized MACs).
- **Guest-isolated Wi-Fi** hides devices from the scan.
- **IPv4 only** — no IPv6 support yet.
- **Single interface** — uses the first private network interface found.
- **Docker on Windows/Mac** cannot see the LAN; run natively.
- **Reverse DNS** is often empty on home routers.
- **Plain HTTP** — do not expose beyond localhost without HTTPS. No login throttling yet.

---

## Project Documentation

| File | Purpose |
|---|---|
| [`docs/BLUEPRINT.md`](docs/BLUEPRINT.md) | Project memory: architecture, API, config, decisions, limits, ideas |
| [`docs/TESTING.md`](docs/TESTING.md) | Manual test lists for every version |
| [`CHANGELOG.md`](CHANGELOG.md) | Full version history |
| [`LICENSE`](LICENSE) | MIT License |

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  Made with ☕ by <a href="https://aajli.com"><strong>AAJLI Abdallah</strong></a><br>
  <a href="mailto:ingenieur.aajli@gmail.com">ingenieur.aajli@gmail.com</a> · <a href="https://github.com/aajli-Abdallah">GitHub</a> · <a href="https://aajli.com">aajli.com</a>
</p>
