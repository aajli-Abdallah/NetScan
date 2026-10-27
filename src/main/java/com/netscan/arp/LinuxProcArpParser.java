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

package com.netscan.arp;

import com.netscan.net.MacUtil;
import java.util.ArrayList;
import java.util.List;

/** Parses /proc/net/arp. Skips incomplete entries (flags 0x0). */
public class LinuxProcArpParser implements ArpParser {
    @Override
    public List<ArpEntry> parse(String raw) {
        List<ArpEntry> out = new ArrayList<>();
        for (String line : raw.split("\\R")) {
            String[] f = line.trim().split("\\s+");
            if (f.length < 4 || !f[0].matches(IP) || f[2].equals("0x0")) continue;
            String mac = MacUtil.normalize(f[3]);
            if (mac != null) out.add(new ArpEntry(f[0], mac));
        }
        return out;
    }
}
