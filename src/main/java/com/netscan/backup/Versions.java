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

public final class Versions {
    private Versions() {}

    /** Numeric compare of dotted versions: 1.0.10 > 1.0.2, 1.0.0.1 > 1.0.0. Unknown parts count as 0. */
    public static int compare(String a, String b) {
        int[] x = parts(a), y = parts(b);
        for (int i = 0; i < Math.max(x.length, y.length); i++) {
            int p = i < x.length ? x[i] : 0, q = i < y.length ? y[i] : 0;
            if (p != q) return Integer.compare(p, q);
        }
        return 0;
    }

    static int[] parts(String v) {
        if (v == null) return new int[0];
        String[] s = v.trim().replaceFirst("^[vV]", "").split("[.\\-]");
        int[] out = new int[s.length];
        for (int i = 0; i < s.length; i++) {
            try {
                out[i] = Integer.parseInt(s[i].replaceAll("\\D.*$", ""));
            } catch (NumberFormatException e) {
                out[i] = 0;
            }
        }
        return out;
    }
}
