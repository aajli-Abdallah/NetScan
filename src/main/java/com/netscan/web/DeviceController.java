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

import com.netscan.model.NetworkInfo;
import com.netscan.model.ScanResult;
import com.netscan.scan.ScanService;
import java.util.Map;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.info.BuildProperties;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class DeviceController {
    private final ScanService scanService;
    private final ObjectProvider<BuildProperties> build;

    public DeviceController(ScanService scanService, ObjectProvider<BuildProperties> build) {
        this.scanService = scanService;
        this.build = build;
    }

    @GetMapping("/devices")
    public ScanResult devices(@RequestParam(defaultValue = "false") boolean refresh) {
        return scanService.scan(refresh);
    }

    @GetMapping("/network")
    public NetworkInfo network() {
        return scanService.network();
    }

    @GetMapping("/info")
    public Map<String, String> info() {
        BuildProperties b = build.getIfAvailable();
        return Map.of("name", "NetScan",
                "version", b == null ? "dev" : b.getVersion(),
                "author", "AAJLI Abdallah",
                "email", "ingenieur.aajli@gmail.com",
                "website", "https://aajli.com",
                "github", "https://github.com/aajli-Abdallah/NetScan",
                "os", System.getProperty("os.name", "?"),
                "java", System.getProperty("java.version", "?"));
    }
}
