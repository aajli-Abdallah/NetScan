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

import java.util.List;
import java.util.function.UnaryOperator;

/** Brings any old backup to the current shape. Add an ordered Step whenever the format changes. */
public final class BackupUpgrader {
    /** A file without appVersion is treated as made by this version. */
    public static final String DEFAULT_VERSION = "1.0.0";

    private record Step(String before, UnaryOperator<Backup> fn) {}

    // Example when the format changes: new Step("1.1.0", b -> ...). Keep them in version order.
    private static final List<Step> STEPS = List.of();

    private BackupUpgrader() {}

    public static Backup upgrade(Backup b) {
        String v = b.appVersion() == null || b.appVersion().isBlank() ? DEFAULT_VERSION : b.appVersion();
        Backup cur = new Backup(v, b.format(), b.exportedAt(), b.devices() == null ? List.of() : b.devices());
        for (Step s : STEPS) if (Versions.compare(v, s.before()) < 0) cur = s.fn().apply(cur);
        return cur;
    }
}
