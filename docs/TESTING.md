# Manual tests

## 1.0.5
1. `mvn test` passes (includes the security and import integration test).
2. No `data/admin.hash` yet: start the app. The log shows `FIRST RUN - sign in with user 'admin' and password '...'`. Open http://localhost:8080/ : you land on the login page. A wrong password is rejected, the right one opens the radar.
3. Restart: the same password still works, nothing new is printed. Setting env `NETSCAN_SECURITY_PASSWORD` and restarting makes that password the valid one.
4. Sign out returns to the login page. Opening `/api/devices` while signed out redirects to the login page.
5. Radar actions still work while signed in: Save label, Forget, Scan ports, Scan now, Test alert. The live dot is green.
6. Backup (JSON) downloads a file with appVersion 1.0.5, format 1 and your devices. Devices (CSV) opens in Excel with correct columns. A label starting with `=` appears as text.
7. Restore: download a backup, change a label, choose the file, mode Replace, Preview, Apply: the old label returns. Choose Merge with the same file: everything is "unchanged".
8. Forget one device, then restore with Merge: it comes back as "new".
9. Open the backup file, delete the `appVersion` line, preview again: it still works (treated as 1.0.0).
10. About 1 minute after start, `data/backups/netscan-backup-<date>.json` exists.
Report: stack trace if start fails; for a login loop, the browser console and the first lines of the log.

## 1.0.4
1. `mvn test` passes (alert rules, webhook formats, baseline/publish).
2. Open the radar page: the dot next to the status is green (live). Stop the app: it turns red. Start again: it turns green by itself.
3. Press "Enable alerts" and allow notifications in the browser.
4. `curl -X POST http://localhost:8080/api/alerts/test`: toast "New unknown device: TEST ALERT", a beep, a desktop notification, and an `ALERT` line in the log.
5. Real alert: join the Wi-Fi with a new device (or a phone with a fresh private MAC), press "Scan now" or wait up to 5 min: toast and notification appear without reloading the page.
6. Mark that device known: later scans produce no alert for it.
7. Baseline: stop the app, delete the `data/` folder, start: first scan lists devices, no toasts, no ALERT lines. Events still show JOINED.
8. Webhook (optional): create an ntfy.sh topic, set `netscan.alert.webhook-url=https://ntfy.sh/<your-secret-topic>`, restart, run the test curl: your phone gets the message.
9. Tiles show Online, Known online, Unknown online, Offline counts and match the radar.
Report: stack trace if start fails. If alerts do not reach the page, send the browser console text.

## 1.0.3
1. `mvn test` passes (OUI, port scanner, ports tests; migration V3 validated).
2. Start the app. `/api/saved` items have hostname and vendor. Without the IEEE file most vendors are null; phones show "Private / randomized MAC".
3. Download the IEEE file (see README), restart, wait for a scan (or press Scan now): vendors fill in for devices with real MACs. Log shows "Loaded N vendor entries".
4. Radar: click a device, you see vendor and hostname. Unlabelled dots now show the hostname.
5. Click "Scan ports" on your router: open ports such as 80 or 443 listed with service names, with a scanned time.
6. Click "Scan ports" on a grey (offline) device: a clear message "Device is offline...".
7. `curl -X POST http://localhost:8080/api/saved/ID/portscan` returns the device with openPorts.
8. This computer shows your computer name as hostname.
Report: stack trace if start fails (a validation error on the new V3 columns would be a small fix).

## 1.0.2
1. `mvn test` passes (new change-detection tests, migration V2 validated).
2. Start the app. After about 20 s the log shows "Scheduled scan: N devices". Repeats every 5 min.
3. Open http://localhost:8080/ : radar sweeps, your devices appear as dots, status line shows last scan and counts.
4. Click a dot: label it, tick Known, Save. The dot turns green, the label appears under it.
5. Switch a phone's Wi-Fi off. After 2 scans (about 10 min) it turns grey and Activity shows "went offline". Switch it on: "came online" after the next scan.
6. Press "Scan now": the button shows Scanning, then the page updates.
7. `/api/events?limit=10` and `/api/status` return JSON.
8. Disconnect the PC from the network during a scan: log warns, no events are created, devices are not marked offline.
9. Set `netscan.scheduler.enabled=false`: no scheduled scans, status says auto-scan off.
Report: stack trace if start fails (a validation error on `online`, `missed` or the events table would be a small fix in V2).

## 1.0.1
1. `mvn test` passes (includes migration + repository test).
2. Start the app: a `data/` folder appears. `/api/devices` items now have id, known, firstSeen, lastSeen. Your PC: known=true.
3. Label one device (replace ID). Windows cmd keeps the escaped quotes; or use Postman/Bruno:
   `curl -X PATCH http://localhost:8080/api/saved/ID -H "Content-Type: application/json" -d "{\"label\":\"Dad phone\",\"known\":true}"`
4. Stop and restart: label and known are still there, firstSeen unchanged, lastSeen newer.
5. `/api/saved?known=false` lists only unknown devices.
6. Switch a phone off: it stays in `/api/saved`, its lastSeen stops moving.
7. DELETE `/api/saved/ID` returns 204; the next scan adds it back as unknown.
8. PATCH a wrong id: 404. Label longer than 100 chars: 400.
Report: stack trace if the app fails at start (a schema validation error would mean the timestamp column type needs a small fix).

## 1.0.0
1. `mvn test` passes (CIDR + ARP parser tests).
2. `mvn spring-boot:run` starts, no errors.
3. `/api/info` shows version 1.0.0.
4. `/api/network` shows your LAN IP, correct subnet, and the right interface (not Docker/VM).
5. `/api/devices`: your router and your own PC (self=true) appear with MACs.
6. Turn on a phone's Wi-Fi, call `/api/devices?refresh=true`: it appears. Turn off, wait 1-2 min, refresh: reachable=false or gone.
7. Disconnect from the network: `/api/network` returns 503 with a clear message.
8. Call `/api/devices` twice within 10 s: second answer is instant (cache).
Report: OS, Java version, and any stack trace.
