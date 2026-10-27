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

import static org.assertj.core.api.Assertions.assertThat;

import com.netscan.store.DeviceEntity;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

class BackupLogicTest {
    static final Instant OLD = Instant.parse("2026-01-01T00:00:00Z");
    static final Instant NEW = Instant.parse("2026-02-01T00:00:00Z");

    private DeviceEntity entity(String label, boolean known, Instant lastSeen) {
        DeviceEntity e = new DeviceEntity();
        e.setId("id1"); e.setMac("AA:BB:CC:DD:EE:01"); e.setLabel(label); e.setKnown(known);
        e.setFirstSeen(OLD); e.setLastSeen(lastSeen);
        return e;
    }

    private Backup.Dev dev(String label, boolean known, Instant first, Instant last) {
        return new Backup.Dev("id1", "AA:BB:CC:DD:EE:01", label, known, "Acme", "host1", "10.0.0.5", first, last, "22", NEW);
    }

    @Test void versionsCompareNumerically() {
        assertThat(Versions.compare("1.0.10", "1.0.2")).isPositive();
        assertThat(Versions.compare("1.0.0.1", "1.0.0")).isPositive();
        assertThat(Versions.compare("1.0", "1.0.0")).isZero();
        assertThat(Versions.compare("dev", "1.0.0")).isNegative();
        assertThat(Versions.compare(null, "1.0.0")).isNegative();
    }

    @Test void upgradeFillsDefaults() {
        Backup b = BackupUpgrader.upgrade(new Backup(null, null, null, null));
        assertThat(b.appVersion()).isEqualTo(BackupUpgrader.DEFAULT_VERSION);
        assertThat(b.devices()).isEmpty();
    }

    @Test void csvQuotesAndNeutralizesFormulas() {
        assertThat(CsvWriter.cell("=1+1")).isEqualTo("'=1+1");
        assertThat(CsvWriter.cell("a,b")).isEqualTo("\"a,b\"");
        assertThat(CsvWriter.cell("say \"hi\"")).isEqualTo("\"say \"\"hi\"\"\"");
        assertThat(CsvWriter.cell(null)).isEmpty();
        assertThat(new CsvWriter().row("x", true).toString()).isEqualTo("\uFEFFx,true\r\n");
    }

    @Test void newerBackupWins() {
        var m = BackupService.merge(entity("Old", false, OLD), dev("Fresh", true, OLD, NEW));
        assertThat(m.label()).isEqualTo("Fresh");
        assertThat(m.known()).isTrue();
        assertThat(m.lastSeen()).isEqualTo(NEW);
    }

    @Test void newerDatabaseKeepsItsValuesButFillsBlanks() {
        DeviceEntity e = entity(null, false, NEW);
        var m = BackupService.merge(e, dev("FromBackup", true, OLD, OLD));
        assertThat(m.known()).isFalse();
        assertThat(m.label()).isEqualTo("FromBackup");
        assertThat(m.lastSeen()).isEqualTo(NEW);
        e.setLabel("Mine");
        assertThat(BackupService.merge(e, dev("FromBackup", true, OLD, OLD)).label()).isEqualTo("Mine");
    }

    @Test void exportThenMergeIsUnchanged() {
        DeviceEntity e = entity("TV", true, NEW);
        e.setVendor("Acme"); e.setHostname("tv"); e.setLastIp("10.0.0.9");
        assertThat(BackupService.merge(e, BackupService.toDev(e)).sameAs(e)).isTrue();
    }

    @Test void nullDevicesAreHandledByUpgrade() {
        assertThat(BackupUpgrader.upgrade(new Backup("1.0.3", 1, null, List.of())).appVersion()).isEqualTo("1.0.3");
    }
}
