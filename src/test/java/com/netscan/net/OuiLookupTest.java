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

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class OuiLookupTest {
    @Test void seedLookup() {
        assertThat(OuiLookup.seedOnly().lookup("00:0C:29:11:22:33")).isEqualTo("VMware");
    }

    @Test void randomizedMacIsPrivate() {
        assertThat(OuiLookup.seedOnly().lookup("DA:A1:19:00:00:01")).isEqualTo(OuiLookup.PRIVATE);
    }

    @Test void unknownIsNull() {
        assertThat(OuiLookup.seedOnly().lookup("00:11:22:33:44:55")).isNull();
        assertThat(OuiLookup.seedOnly().lookup(null)).isNull();
    }

    @Test void parsesIeeeAndSimpleRows() {
        assertThat(OuiLookup.parseEntry("MA-L,286FB9,\"Nokia Shanghai Bell Co., Ltd.\",\"Some Road\""))
                .containsExactly("286FB9", "Nokia Shanghai Bell Co., Ltd.");
        assertThat(OuiLookup.parseEntry("aabbcc,Acme")).containsExactly("AABBCC", "Acme");
        assertThat(OuiLookup.parseEntry("Registry,Assignment,Organization Name,Organization Address")).isNull();
        assertThat(OuiLookup.parseEntry("MA-S,70B3D5E00,Foo,Bar")).isNull();
    }

    @Test void externalFileOverridesSeed(@TempDir Path dir) throws Exception {
        Path f = dir.resolve("oui.csv");
        Files.writeString(f, "000C29,Override Corp\n001122,Brand New\n");
        OuiLookup o = new OuiLookup(f.toString());
        assertThat(o.lookup("00:0C:29:00:00:01")).isEqualTo("Override Corp");
        assertThat(o.lookup("00:11:22:00:00:01")).isEqualTo("Brand New");
    }
}
