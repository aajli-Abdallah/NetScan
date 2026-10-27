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

import com.netscan.model.ScanResult;
import com.netscan.store.DeviceStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@EnableScheduling
@ConditionalOnProperty(name = "netscan.scheduler.enabled", havingValue = "true", matchIfMissing = true)
public class ScanScheduler {
    private static final Logger log = LoggerFactory.getLogger(ScanScheduler.class);
    private final ScanService scans;
    private final DeviceStore store;
    private final int retentionDays;

    public ScanScheduler(ScanService scans, DeviceStore store,
                         @Value("${netscan.events-retention-days:90}") int retentionDays) {
        this.scans = scans;
        this.store = store;
        this.retentionDays = retentionDays;
    }

    @Scheduled(fixedDelayString = "${netscan.scan-interval:PT5M}",
               initialDelayString = "${netscan.scan-initial-delay:PT20S}")
    public void scheduledScan() {
        try {
            ScanResult r = scans.scan(true);
            log.info("Scheduled scan: {} devices in {} ms", r.count(), r.durationMs());
        } catch (Exception e) {
            log.warn("Scheduled scan skipped: {}", e.getMessage());
        }
    }

    @Scheduled(cron = "0 30 3 * * *")
    public void purgeOldEvents() {
        int n = store.purgeEvents(retentionDays);
        if (n > 0) log.info("Purged {} old events", n);
    }
}
