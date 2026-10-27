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

package com.netscan.arp;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/** Picks the right source and parser for the current OS. */
@Component
public class ArpReader {
    private static final Logger log = LoggerFactory.getLogger(ArpReader.class);
    private static final Path PROC = Path.of("/proc/net/arp");

    public List<ArpEntry> read() {
        String os = System.getProperty("os.name", "").toLowerCase();
        try {
            if (os.contains("linux") && Files.exists(PROC))
                return new LinuxProcArpParser().parse(Files.readString(PROC));
            if (os.contains("win"))
                return new WindowsArpParser().parse(run("arp", "-a"));
            return new MacArpParser().parse(run("arp", "-an"));
        } catch (Exception e) {
            log.warn("Could not read ARP table: {}", e.toString());
            return List.of();
        }
    }

    private String run(String... cmd) throws IOException {
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        return new String(p.getInputStream().readAllBytes());
    }
}
