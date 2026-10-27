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

import com.netscan.model.Device;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Reverse DNS for reachable devices, in parallel, with one shared deadline. */
@Component
public class HostnameResolver {
    private final long deadlineMs;

    public HostnameResolver(@Value("${netscan.hostname-timeout-ms:2000}") long deadlineMs) {
        this.deadlineMs = deadlineMs;
    }

    public List<Device> attach(List<Device> devices) {
        ExecutorService ex = Executors.newVirtualThreadPerTaskExecutor();
        Map<String, Future<String>> jobs = new HashMap<>();
        for (Device d : devices)
            if (d.reachable() && !d.self()) jobs.put(d.ip(), ex.submit(() -> lookup(d.ip())));
        long end = System.currentTimeMillis() + deadlineMs;
        List<Device> out = new ArrayList<>();
        for (Device d : devices) {
            String host = null;
            if (d.self()) {
                host = localName();
            } else {
                Future<String> f = jobs.get(d.ip());
                if (f != null) {
                    try {
                        host = f.get(Math.max(1, end - System.currentTimeMillis()), TimeUnit.MILLISECONDS);
                    } catch (Exception e) {
                        f.cancel(true);
                    }
                }
            }
            out.add(host == null ? d : d.withHostname(host));
        }
        ex.shutdownNow();
        return out;
    }

    private static String lookup(String ip) throws Exception {
        String h = InetAddress.getByName(ip).getCanonicalHostName();
        if (h == null || h.equals(ip)) return null;
        return h.endsWith(".") ? h.substring(0, h.length() - 1) : h;
    }

    private static String localName() {
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (Exception e) {
            return null;
        }
    }
}
