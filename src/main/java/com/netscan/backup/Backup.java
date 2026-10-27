/*
 * Copyright (c) 2026 AAJLI Abdallah
 * Email: ingenieur.aajli@gmail.com
 * GitHub: https://github.com/aajli-Abdallah
 * Website: https://aajli.com
 *
 * This source code is part of the NetScan project — a home network scanner
 * and intruder-alert system. All rights reserved.
 *
 * For license details, see the LICENSE file in the project root.
 */

package com.netscan.backup;

import java.time.Instant;
import java.util.List;

/** Backup file format. Unknown fields are ignored on import, so older apps can read newer files. */
public record Backup(String appVersion, Integer format, Instant exportedAt, List<Dev> devices) {
    public record Dev(String id, String mac, String label, boolean known, String vendor, String hostname,
                      String lastIp, Instant firstSeen, Instant lastSeen, String openPorts,
                      Instant portsScannedAt) {}
}
