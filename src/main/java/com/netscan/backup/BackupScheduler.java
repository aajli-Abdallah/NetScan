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

package com.netscan.backup;

import java.nio.file.Path;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/** Hourly check: if today's local backup is missing, write it (works even if the PC was off at night). */
@Component
@EnableScheduling
@ConditionalOnProperty(name = "netscan.backup.enabled", havingValue = "true", matchIfMissing = true)
public class BackupScheduler {
    private static final Logger log = LoggerFactory.getLogger(BackupScheduler.class);
    private final BackupService service;

    public BackupScheduler(BackupService service) {
        this.service = service;
    }

    @Scheduled(initialDelayString = "PT1M", fixedDelayString = "PT1H")
    public void ensureToday() {
        try {
            Path f = service.ensureTodayBackup();
            if (f != null) log.info("Daily backup written: {}", f);
        } catch (Exception e) {
            log.warn("Daily backup failed: {}", e.toString());
        }
    }
}
