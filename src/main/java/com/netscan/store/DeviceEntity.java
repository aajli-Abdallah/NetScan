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

@Entity
@Table(name = "devices")
public class DeviceEntity {
    @Id @Column(length = 36) private String id;
    @Column(nullable = false, unique = true, length = 17) private String mac;
    @Column(length = 100) private String label;
    @Column(nullable = false) private boolean known;
    @Column(name = "last_ip", length = 45) private String lastIp;
    @Column(name = "first_seen", nullable = false) private Instant firstSeen;
    @Column(name = "last_seen", nullable = false) private Instant lastSeen;
    @Column(nullable = false) private boolean online;
    @Column(nullable = false) private int missed;
    @Column(length = 100) private String vendor;
    @Column(length = 255) private String hostname;
    @Column(name = "open_ports", length = 255) private String openPorts;
    @Column(name = "ports_scanned_at") private Instant portsScannedAt;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getMac() { return mac; }
    public void setMac(String mac) { this.mac = mac; }
    public String getLabel() { return label; }
    public void setLabel(String label) { this.label = label; }
    public boolean isKnown() { return known; }
    public void setKnown(boolean known) { this.known = known; }
    public String getLastIp() { return lastIp; }
    public void setLastIp(String lastIp) { this.lastIp = lastIp; }
    public Instant getFirstSeen() { return firstSeen; }
    public void setFirstSeen(Instant firstSeen) { this.firstSeen = firstSeen; }
    public Instant getLastSeen() { return lastSeen; }
    public void setLastSeen(Instant lastSeen) { this.lastSeen = lastSeen; }
    public boolean isOnline() { return online; }
    public void setOnline(boolean online) { this.online = online; }
    public int getMissed() { return missed; }
    public void setMissed(int missed) { this.missed = missed; }
    public String getVendor() { return vendor; }
    public void setVendor(String vendor) { this.vendor = vendor; }
    public String getHostname() { return hostname; }
    public void setHostname(String hostname) { this.hostname = hostname; }
    public String getOpenPorts() { return openPorts; }
    public void setOpenPorts(String openPorts) { this.openPorts = openPorts; }
    public Instant getPortsScannedAt() { return portsScannedAt; }
    public void setPortsScannedAt(Instant portsScannedAt) { this.portsScannedAt = portsScannedAt; }
}
