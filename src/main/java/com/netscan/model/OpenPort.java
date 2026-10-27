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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public record OpenPort(int port, String service) {
    private static final Map<Integer, String> NAMES = Map.ofEntries(
            Map.entry(21, "FTP"), Map.entry(22, "SSH"), Map.entry(23, "Telnet"), Map.entry(53, "DNS"),
            Map.entry(80, "HTTP"), Map.entry(139, "NetBIOS"), Map.entry(443, "HTTPS"), Map.entry(445, "SMB"),
            Map.entry(554, "RTSP (camera)"), Map.entry(631, "IPP (printer)"), Map.entry(1883, "MQTT"),
            Map.entry(3389, "RDP"), Map.entry(5900, "VNC"), Map.entry(8080, "HTTP alt"),
            Map.entry(8443, "HTTPS alt"), Map.entry(9100, "Printer (raw)"));

    public static OpenPort of(int port) {
        return new OpenPort(port, NAMES.getOrDefault(port, "unknown"));
    }

    /** "22,80" -> list. Null, empty or bad numbers are ignored. */
    public static List<OpenPort> parse(String csv) {
        List<OpenPort> out = new ArrayList<>();
        if (csv == null || csv.isBlank()) return out;
        for (String s : csv.split(",")) {
            try {
                out.add(of(Integer.parseInt(s.trim())));
            } catch (NumberFormatException ignored) { }
        }
        return out;
    }

    public static String format(List<Integer> ports) {
        return String.join(",", ports.stream().map(String::valueOf).toList());
    }
}
