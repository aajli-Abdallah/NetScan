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

import static org.assertj.core.api.Assertions.assertThat;

import com.netscan.net.MacUtil;
import org.junit.jupiter.api.Test;

class ArpParsersTest {
    @Test void linuxSkipsHeaderAndIncomplete() {
        String raw = """
                IP address       HW type     Flags       HW address            Mask     Device
                192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0
                192.168.1.77     0x1         0x0         00:00:00:00:00:00     *        wlan0
                """;
        assertThat(new LinuxProcArpParser().parse(raw))
                .containsExactly(new ArpEntry("192.168.1.1", "AA:BB:CC:DD:EE:FF"));
    }

    @Test void windowsParsesEntriesAndDropsBroadcast() {
        String raw = """
                Interface: 192.168.1.20 --- 0x7
                  Internet Address      Physical Address      Type
                  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic
                  192.168.1.255         ff-ff-ff-ff-ff-ff     static
                  224.0.0.22            01-00-5e-00-00-16     static
                """;
        var r = new WindowsArpParser().parse(raw);
        assertThat(r).hasSize(2);
        assertThat(r.get(0)).isEqualTo(new ArpEntry("192.168.1.1", "AA:BB:CC:DD:EE:FF"));
    }

    @Test void macPadsOctetsAndSkipsIncomplete() {
        String raw = """
                ? (192.168.1.1) at a4:b:cc:dd:ee:f on en0 ifscope [ethernet]
                ? (192.168.1.50) at (incomplete) on en0 ifscope [ethernet]
                ? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
                """;
        assertThat(new MacArpParser().parse(raw))
                .containsExactly(new ArpEntry("192.168.1.1", "A4:0B:CC:DD:EE:0F"));
    }

    @Test void macUtilRejectsGarbage() {
        assertThat(MacUtil.normalize("xx:yy")).isNull();
        assertThat(MacUtil.normalize(null)).isNull();
        assertThat(MacUtil.normalize("00:00:00:00:00:00")).isNull();
    }
}
