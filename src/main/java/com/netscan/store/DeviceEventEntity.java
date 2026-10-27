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

package com.netscan.store;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "device_events")
public class DeviceEventEntity {
    @Id @Column(length = 36) private String id;
    @Column(name = "device_id", nullable = false, length = 36) private String deviceId;
    @Column(nullable = false, length = 17) private String mac;
    @Column(length = 100) private String label;
    @Column(length = 45) private String ip;
    @Column(nullable = false) private boolean known;
    @Column(nullable = false, length = 10) private String type;
    @Column(name = "occurred_at", nullable = false) private Instant occurredAt;

    public static DeviceEventEntity of(DeviceEntity d, String type, Instant at) {
        DeviceEventEntity e = new DeviceEventEntity();
        e.id = UUID.randomUUID().toString();
        e.deviceId = d.getId();
        e.mac = d.getMac();
        e.label = d.getLabel();
        e.ip = d.getLastIp();
        e.known = d.isKnown();
        e.type = type;
        e.occurredAt = at;
        return e;
    }

    public String getId() { return id; }
    public String getDeviceId() { return deviceId; }
    public String getMac() { return mac; }
    public String getLabel() { return label; }
    public String getIp() { return ip; }
    public boolean isKnown() { return known; }
    public String getType() { return type; }
    public Instant getOccurredAt() { return occurredAt; }
}
