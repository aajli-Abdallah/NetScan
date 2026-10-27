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

package com.netscan.net;

public final class MacUtil {
    private MacUtil() {}

    /** Returns AA:BB:CC:DD:EE:FF, or null if invalid, all-zero or broadcast. Pads short octets (macOS). */
    public static String normalize(String raw) {
        if (raw == null) return null;
        String[] p = raw.trim().split("[:-]");
        if (p.length != 6) return null;
        StringBuilder sb = new StringBuilder();
        for (String s : p) {
            if (s.isEmpty() || s.length() > 2 || !s.matches("[0-9a-fA-F]+")) return null;
            if (sb.length() > 0) sb.append(':');
            sb.append(s.length() == 1 ? "0" + s : s);
        }
        String mac = sb.toString().toUpperCase();
        if (mac.equals("00:00:00:00:00:00") || mac.equals("FF:FF:FF:FF:FF:FF")) return null;
        return mac;
    }

    public static String format(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) {
            if (sb.length() > 0) sb.append(':');
            sb.append(String.format("%02X", x));
        }
        return sb.toString();
    }
}
