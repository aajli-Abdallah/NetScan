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
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class CidrTest {
    @Test void normalizesNetworkAddress() {
        assertThat(Cidr.parse("192.168.1.57/24").toString()).isEqualTo("192.168.1.0/24");
        assertThat(Cidr.parse("10.0.17.5/20").toString()).isEqualTo("10.0.16.0/20");
    }

    @Test void slash24Hosts() {
        var h = Cidr.parse("192.168.1.0/24").hosts();
        assertThat(h).hasSize(254);
        assertThat(h.get(0)).isEqualTo("192.168.1.1");
        assertThat(h.get(253)).isEqualTo("192.168.1.254");
    }

    @Test void slash30HasTwoHosts() {
        assertThat(Cidr.parse("192.168.1.4/30").hosts()).containsExactly("192.168.1.5", "192.168.1.6");
    }

    @Test void slash20Size() {
        assertThat(Cidr.parse("10.0.16.0/20").hosts()).hasSize(4094);
    }

    @Test void broadcastAndContains() {
        Cidr c = Cidr.parse("192.168.1.0/24");
        assertThat(c.broadcast()).isEqualTo("192.168.1.255");
        assertThat(c.contains("192.168.1.99")).isTrue();
        assertThat(c.contains("192.168.2.1")).isFalse();
        assertThat(c.contains("garbage")).isFalse();
    }

    @Test void isHostExcludesNetworkAndBroadcast() {
        Cidr c = Cidr.parse("192.168.1.0/24");
        assertThat(c.isHost("192.168.1.0")).isFalse();
        assertThat(c.isHost("192.168.1.255")).isFalse();
        assertThat(c.isHost("192.168.1.1")).isTrue();
    }

    @Test void rejectsBadInput() {
        assertThrows(IllegalArgumentException.class, () -> Cidr.parse("192.168.1.0"));
        assertThrows(IllegalArgumentException.class, () -> Cidr.parse("192.168.1.0/abc"));
        assertThrows(IllegalArgumentException.class, () -> Cidr.parse("192.168.1.0/31"));
        assertThrows(IllegalArgumentException.class, () -> Cidr.parse("300.1.1.1/24"));
        assertThrows(IllegalArgumentException.class, () -> Cidr.parse("10.0.0.0/8").hosts());
    }
}
