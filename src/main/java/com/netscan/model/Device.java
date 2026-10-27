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

/** reachable=false with a MAC means "in ARP cache only" (maybe offline or blocking probes). */
public record Device(String ip, String mac, boolean reachable, boolean self, String hostname) {
    public Device(String ip, String mac, boolean reachable, boolean self) {
        this(ip, mac, reachable, self, null);
    }

    public Device withHostname(String h) {
        return new Device(ip, mac, reachable, self, h);
    }
}
