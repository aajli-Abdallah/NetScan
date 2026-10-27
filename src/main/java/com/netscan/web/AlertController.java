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

package com.netscan.web;

import com.netscan.alert.AlertService;
import com.netscan.alert.EventHub;
import com.netscan.alert.WebhookNotifier;
import com.netscan.model.DeviceEvent;
import java.time.Instant;
import java.util.Map;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

@RestController
@RequestMapping("/api")
public class AlertController {
    private final EventHub hub;
    private final WebhookNotifier webhook;

    public AlertController(EventHub hub, WebhookNotifier webhook) {
        this.hub = hub;
        this.webhook = webhook;
    }

    @GetMapping(path = "/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter stream() {
        return hub.subscribe();
    }

    /** Sends a fake alert to the page and the webhook so you can check your setup. Writes nothing to the database. */
    @PostMapping("/alerts/test")
    public Map<String, Object> test() {
        DeviceEvent e = new DeviceEvent("test", "test", "00:00:00:00:00:00", "TEST ALERT", "0.0.0.0",
                false, "JOINED", Instant.now());
        hub.publish("device", e);
        webhook.send(AlertService.message(e));
        return Map.of("sentToPage", true, "webhookConfigured", webhook.enabled());
    }
}
