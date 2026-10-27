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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * MAC -> vendor. Built-in seed, then an optional external file (IEEE oui.csv or "AABBCC,Vendor")
 * that overrides it. Only 24-bit (MA-L) blocks are used.
 */
@Component
public class OuiLookup {
    public static final String PRIVATE = "Private / randomized MAC";
    private static final Logger log = LoggerFactory.getLogger(OuiLookup.class);
    private final Map<String, String> map = new HashMap<>();

    public OuiLookup(@Value("${netscan.oui-file:./data/oui.csv}") String externalPath) {
        try (InputStream in = OuiLookup.class.getResourceAsStream("/oui-seed.csv")) {
            if (in != null) load(in);
        } catch (IOException e) {
            log.warn("Could not read built-in vendor seed: {}", e.toString());
        }
        int seed = map.size();
        Path p = Path.of(externalPath == null ? "" : externalPath);
        if (!externalPath.isBlank() && Files.isRegularFile(p)) {
            try (InputStream in = Files.newInputStream(p)) {
                load(in);
                log.info("Loaded {} vendor entries from {}", map.size() - seed, p);
            } catch (IOException e) {
                log.warn("Could not read {}: {}", p, e.toString());
            }
        } else {
            log.info("Vendor list: {} built-in entries (add data/oui.csv for full coverage)", seed);
        }
    }

    public static OuiLookup seedOnly() {
        return new OuiLookup("");
    }

    /** Vendor name, PRIVATE for randomized MACs, or null if unknown. */
    public String lookup(String mac) {
        if (mac == null || mac.length() < 8) return null;
        if (isRandomized(mac)) return PRIVATE;
        return map.get(mac.substring(0, 8).replace(":", "").toUpperCase());
    }

    static boolean isRandomized(String mac) {
        try {
            return (Integer.parseInt(mac.substring(0, 2), 16) & 0x02) != 0;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private void load(InputStream in) throws IOException {
        BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
        String line;
        while ((line = r.readLine()) != null) {
            String[] e = parseEntry(line);
            if (e != null) map.put(e[0], e[1]);
        }
    }

    /** Returns {KEY6, name} or null. Accepts "AABBCC,Name" and IEEE rows "MA-L,AABBCC,Name,Address". */
    static String[] parseEntry(String line) {
        List<String> f = splitCsv(line);
        int i;
        if (f.size() >= 2 && f.get(0).trim().matches("(?i)[0-9a-f]{6}")) i = 0;
        else if (f.size() >= 3 && f.get(1).trim().matches("(?i)[0-9a-f]{6}")) i = 1;
        else return null;
        String name = f.get(i + 1).trim();
        if (name.isEmpty()) return null;
        return new String[]{f.get(i).trim().toUpperCase(), name};
    }

    static List<String> splitCsv(String line) {
        List<String> out = new ArrayList<>();
        StringBuilder sb = new StringBuilder();
        boolean quoted = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '"') {
                if (quoted && i + 1 < line.length() && line.charAt(i + 1) == '"') { sb.append('"'); i++; }
                else quoted = !quoted;
            } else if (c == ',' && !quoted) {
                out.add(sb.toString());
                sb.setLength(0);
            } else {
                sb.append(c);
            }
        }
        out.add(sb.toString());
        return out;
    }
}
