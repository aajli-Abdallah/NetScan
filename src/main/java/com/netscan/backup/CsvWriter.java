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

/** Minimal CSV builder. Neutralizes spreadsheet formulas (labels are user input). UTF-8 BOM for Excel. */
public final class CsvWriter {
    private final StringBuilder sb = new StringBuilder("\uFEFF");

    public CsvWriter row(Object... cells) {
        for (int i = 0; i < cells.length; i++) {
            if (i > 0) sb.append(',');
            sb.append(cell(cells[i]));
        }
        sb.append("\r\n");
        return this;
    }

    static String cell(Object o) {
        if (o == null) return "";
        String s = o.toString();
        if (!s.isEmpty() && "=+-@\t\r".indexOf(s.charAt(0)) >= 0) s = "'" + s;
        if (s.contains(",") || s.contains("\"") || s.contains("\n") || s.contains("\r"))
            s = "\"" + s.replace("\"", "\"\"") + "\"";
        return s;
    }

    @Override
    public String toString() {
        return sb.toString();
    }
}
