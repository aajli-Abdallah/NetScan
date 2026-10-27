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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Parses `arp -an` (macOS/BSD): "? (192.168.1.1) at a4:b:cc:dd:ee:f on en0 ...". */
public class MacArpParser implements ArpParser {
    private static final Pattern LINE = Pattern.compile("\\((" + IP + ")\\)\\s+at\\s+([0-9a-fA-F:]+)");

    @Override
    public List<ArpEntry> parse(String raw) {
        List<ArpEntry> out = new ArrayList<>();
        for (String line : raw.split("\\R")) {
            Matcher m = LINE.matcher(line);
            if (!m.find()) continue;
            String mac = MacUtil.normalize(m.group(2));
            if (mac != null) out.add(new ArpEntry(m.group(1), mac));
        }
        return out;
    }
}
