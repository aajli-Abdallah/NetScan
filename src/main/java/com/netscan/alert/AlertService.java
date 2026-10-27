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

import com.netscan.model.DeviceChanged;
import com.netscan.model.DeviceEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

/** Runs after the scan transaction committed: push to the page, log and webhook for real alerts. */
@Component
public class AlertService {
    private static final Logger log = LoggerFactory.getLogger(AlertService.class);
    private final EventHub hub;
    private final WebhookNotifier webhook;

    public AlertService(EventHub hub, WebhookNotifier webhook) {
        this.hub = hub;
        this.webhook = webhook;
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void on(DeviceChanged change) {
        DeviceEvent e = change.event();
        hub.publish("device", e);
        if (isAlert(e)) {
            String msg = message(e);
            log.warn("ALERT: {}", msg);
            webhook.send(msg);
        }
    }

    /** A device with a new MAC that is not known. */
    public static boolean isAlert(DeviceEvent e) {
        return "JOINED".equals(e.type()) && !e.known();
    }

    public static String message(DeviceEvent e) {
        return "New unknown device on your network: " + (e.label() != null ? e.label() + " " : "")
                + e.mac() + (e.ip() != null ? " (" + e.ip() + ")" : "");
    }
}
