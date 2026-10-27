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

package com.netscan.alert;

import static org.assertj.core.api.Assertions.assertThat;

import com.netscan.model.DeviceEvent;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class AlertTest {
    private DeviceEvent ev(String type, boolean known) {
        return new DeviceEvent("1", "d1", "AA:BB:CC:DD:EE:01", null, "192.168.1.9", known, type, Instant.now());
    }

    @Test void onlyNewUnknownDevicesAlert() {
        assertThat(AlertService.isAlert(ev("JOINED", false))).isTrue();
        assertThat(AlertService.isAlert(ev("JOINED", true))).isFalse();
        assertThat(AlertService.isAlert(ev("ONLINE", false))).isFalse();
        assertThat(AlertService.isAlert(ev("OFFLINE", false))).isFalse();
    }

    @Test void messageHasMacAndIp() {
        assertThat(AlertService.message(ev("JOINED", false)))
                .contains("AA:BB:CC:DD:EE:01").contains("192.168.1.9");
    }

    @Test void webhookBodyFormats() {
        assertThat(WebhookNotifier.body("text", "hi")).isEqualTo("hi");
        assertThat(WebhookNotifier.body(null, "hi")).isEqualTo("hi");
        assertThat(WebhookNotifier.body("discord", "say \"x\"")).isEqualTo("{\"content\":\"say \\\"x\\\"\"}");
        assertThat(WebhookNotifier.body("Telegram", "a\nb")).isEqualTo("{\"text\":\"a\\nb\"}");
    }

    @Test void webhookDisabledWithoutUrl() {
        assertThat(new WebhookNotifier("", "text").enabled()).isFalse();
        assertThat(new WebhookNotifier("https://ntfy.sh/x", "text").enabled()).isTrue();
    }
}
