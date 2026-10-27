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

import com.netscan.model.DeviceEvent;
import com.netscan.model.ScanResult;
import com.netscan.scan.ScanService;
import com.netscan.store.DeviceStore;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class HistoryController {
    private final DeviceStore store;
    private final ScanService scans;
    private final Duration interval;
    private final boolean schedulerEnabled;

    public HistoryController(DeviceStore store, ScanService scans,
                             @Value("${netscan.scan-interval:PT5M}") Duration interval,
                             @Value("${netscan.scheduler.enabled:true}") boolean schedulerEnabled) {
        this.store = store;
        this.scans = scans;
        this.interval = interval;
        this.schedulerEnabled = schedulerEnabled;
    }

    @GetMapping("/events")
    public List<DeviceEvent> events(@RequestParam(required = false) String deviceId,
                                    @RequestParam(defaultValue = "50") int limit) {
        return store.events(deviceId, limit);
    }

    /** Never triggers a scan. */
    @GetMapping("/status")
    public Map<String, Object> status() {
        ScanResult r = scans.lastResult();
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("lastScanAt", r == null ? null : r.scannedAt());
        m.put("lastScanMs", r == null ? null : r.durationMs());
        m.put("deviceCount", r == null ? 0 : r.count());
        m.put("intervalSeconds", interval.toSeconds());
        m.put("schedulerEnabled", schedulerEnabled);
        return m;
    }
}
