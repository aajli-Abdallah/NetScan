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

/** Scanned device merged with stored data. reachable = answered this scan; online = debounced state. */
public record DeviceView(String id, String ip, String mac, String label, String hostname, String vendor,
                         boolean known, boolean online, boolean reachable, boolean self,
                         Instant firstSeen, Instant lastSeen) {}
