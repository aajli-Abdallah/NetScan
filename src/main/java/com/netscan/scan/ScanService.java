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

package com.netscan.scan;

import com.netscan.arp.ArpEntry;
import com.netscan.alert.EventHub;
import com.netscan.arp.ArpReader;
import com.netscan.model.Device;
import com.netscan.model.DeviceView;
import com.netscan.model.NetworkInfo;
import com.netscan.model.ScanResult;
import com.netscan.net.Cidr;
import com.netscan.store.DeviceStore;
import java.time.Instant;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class ScanService {
    private final NetworkDetector detector;
    private final PingSweeper sweeper;
    private final ArpReader arpReader;
    private final DeviceStore store;
    private final HostnameResolver hostnames;
    private final EventHub hub;
    private final long cacheMs;
    private volatile ScanResult last;
    private long lastAt;

    public ScanService(NetworkDetector detector, PingSweeper sweeper, ArpReader arpReader,
                       DeviceStore store,
                       HostnameResolver hostnames,
                       EventHub hub,
                       @Value("${netscan.cache-seconds:10}") long cacheSeconds) {
        this.detector = detector;
        this.sweeper = sweeper;
        this.arpReader = arpReader;
        this.store = store;
        this.hostnames = hostnames;
        this.hub = hub;
        this.cacheMs = cacheSeconds * 1000;
    }

    /** Last scan without scanning (null before the first scan). */
    public ScanResult lastResult() {
        return last;
    }

    public NetworkInfo network() {
        return detector.detect().orElseThrow(() -> new ResponseStatusException(
                HttpStatus.SERVICE_UNAVAILABLE, "No active private IPv4 network interface found"));
    }

    /** One scan at a time; results are cached briefly so repeated calls are cheap. */
    public synchronized ScanResult scan(boolean force) {
        long now = System.currentTimeMillis();
        if (!force && last != null && now - lastAt < cacheMs) return last;

        NetworkInfo net = network();
        Cidr range = Cidr.parse(net.scanRange());
        Set<String> alive = sweeper.sweep(range.hosts());

        Map<String, String> arp = new HashMap<>();
        for (ArpEntry e : arpReader.read()) if (range.isHost(e.ip())) arp.put(e.ip(), e.mac());

        Set<String> ips = new HashSet<>(alive);
        ips.addAll(arp.keySet());
        ips.add(net.localIp());

        List<Device> found = ips.stream()
                .sorted(Comparator.comparingLong(Cidr::toLong))
                .map(ip -> {
                    boolean self = ip.equals(net.localIp());
                    return new Device(ip, self ? net.localMac() : arp.get(ip), self || alive.contains(ip), self);
                })
                .toList();
        List<Device> devices = hostnames.attach(found);

        Instant at = Instant.now();
        List<DeviceView> views = store.sync(devices, at);
        last = new ScanResult(net, at, System.currentTimeMillis() - now, views.size(), views);
        lastAt = System.currentTimeMillis();
        hub.publish("scan", Map.of("at", at.toString(), "count", views.size()));
        return last;
    }
}
