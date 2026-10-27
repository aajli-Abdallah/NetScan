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

import java.util.ArrayList;
import java.util.List;

/** IPv4 subnet math. Prefix 1-30. Pure logic, no I/O. */
public final class Cidr {
    private final long network;
    private final int prefix;

    private Cidr(long network, int prefix) {
        this.network = network;
        this.prefix = prefix;
    }

    public static Cidr parse(String text) {
        String[] p = text.trim().split("/");
        if (p.length != 2) throw new IllegalArgumentException("Expected a.b.c.d/n: " + text);
        try {
            return of(p[0].trim(), Integer.parseInt(p[1].trim()));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Bad prefix: " + text);
        }
    }

    public static Cidr of(String ip, int prefix) {
        if (prefix < 1 || prefix > 30) throw new IllegalArgumentException("Prefix must be 1-30: " + prefix);
        long mask = (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
        return new Cidr(toLong(ip) & mask, prefix);
    }

    public static long toLong(String ip) {
        String[] o = ip.trim().split("\\.");
        if (o.length != 4) throw new IllegalArgumentException("Bad IPv4: " + ip);
        long v = 0;
        for (String s : o) {
            int n;
            try {
                n = Integer.parseInt(s);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Bad IPv4: " + ip);
            }
            if (n < 0 || n > 255) throw new IllegalArgumentException("Bad IPv4: " + ip);
            v = (v << 8) | n;
        }
        return v;
    }

    public static String toIp(long v) {
        return ((v >> 24) & 255) + "." + ((v >> 16) & 255) + "." + ((v >> 8) & 255) + "." + (v & 255);
    }

    private long size() { return 1L << (32 - prefix); }

    public int prefix() { return prefix; }
    public long hostCount() { return size() - 2; }
    public String network() { return toIp(network); }
    public String broadcast() { return toIp(network + size() - 1); }

    /** All usable host addresses. Refuses ranges larger than /16. */
    public List<String> hosts() {
        if (prefix < 16) throw new IllegalArgumentException("Range too large to enumerate: " + this);
        List<String> out = new ArrayList<>((int) hostCount());
        for (long v = network + 1; v < network + size() - 1; v++) out.add(toIp(v));
        return out;
    }

    public boolean contains(String ip) {
        try {
            long v = toLong(ip);
            return v >= network && v < network + size();
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /** In range and not the network or broadcast address. */
    public boolean isHost(String ip) {
        if (!contains(ip)) return false;
        long v = toLong(ip);
        return v != network && v != network + size() - 1;
    }

    @Override
    public String toString() { return network() + "/" + prefix; }
}
