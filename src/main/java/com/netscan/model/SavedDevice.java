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

package com.netscan.model;

import java.time.Instant;
import java.util.List;

public record SavedDevice(String id, String mac, String lastIp, String label, String hostname, String vendor,
                          boolean known, boolean online, Instant firstSeen, Instant lastSeen,
                          List<OpenPort> openPorts, Instant portsScannedAt) {}
