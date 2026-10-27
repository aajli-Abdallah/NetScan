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

import com.netscan.backup.Backup;
import com.netscan.backup.BackupService;
import com.netscan.backup.BackupService.Mode;
import com.netscan.backup.BackupService.Result;
import java.time.LocalDate;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class ExportController {
    private static final MediaType CSV = MediaType.parseMediaType("text/csv; charset=utf-8");
    private final BackupService service;

    public ExportController(BackupService service) {
        this.service = service;
    }

    private static String attachment(String name) {
        return ContentDisposition.attachment().filename(name).build().toString();
    }

    @GetMapping("/export/backup.json")
    public ResponseEntity<Backup> backup() {
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, attachment("netscan-backup-" + LocalDate.now() + ".json"))
                .body(service.export());
    }

    @GetMapping("/export/devices.csv")
    public ResponseEntity<String> devicesCsv() {
        return ResponseEntity.ok().contentType(CSV)
                .header(HttpHeaders.CONTENT_DISPOSITION, attachment("netscan-devices-" + LocalDate.now() + ".csv"))
                .body(service.devicesCsv());
    }

    @GetMapping("/export/events.csv")
    public ResponseEntity<String> eventsCsv() {
        return ResponseEntity.ok().contentType(CSV)
                .header(HttpHeaders.CONTENT_DISPOSITION, attachment("netscan-events-" + LocalDate.now() + ".csv"))
                .body(service.eventsCsv());
    }

    /** Shows what an import would do. Writes nothing. */
    @PostMapping("/import/preview")
    public Result preview(@RequestBody Backup backup, @RequestParam(defaultValue = "merge") String mode) {
        return service.run(backup, Mode.parse(mode), false);
    }

    @PostMapping("/import")
    public Result apply(@RequestBody Backup backup, @RequestParam(defaultValue = "merge") String mode) {
        return service.run(backup, Mode.parse(mode), true);
    }
}
