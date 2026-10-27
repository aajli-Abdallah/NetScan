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

import java.io.IOException;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Probes every host in parallel (virtual threads). A host is alive if it answers
 * ping/echo, accepts a TCP connection, or actively refuses one (refused = host is up).
 */
@Component
public class PingSweeper {
    private final int timeoutMs;
    private final int[] ports;

    public PingSweeper(@Value("${netscan.timeout-ms:300}") int timeoutMs,
                       @Value("${netscan.probe-ports:80,443,22,53,445}") int[] ports) {
        this.timeoutMs = timeoutMs;
        this.ports = ports;
    }

    public Set<String> sweep(List<String> ips) {
        Set<String> alive = ConcurrentHashMap.newKeySet();
        try (ExecutorService ex = Executors.newVirtualThreadPerTaskExecutor()) {
            for (String ip : ips) ex.submit(() -> { if (isAlive(ip)) alive.add(ip); });
        }
        return alive;
    }

    boolean isAlive(String ip) {
        try {
            if (InetAddress.getByName(ip).isReachable(timeoutMs)) return true;
        } catch (IOException ignored) { }
        for (int port : ports) {
            try (Socket s = new Socket()) {
                s.connect(new InetSocketAddress(ip, port), timeoutMs);
                return true;
            } catch (ConnectException e) {
                String m = e.getMessage();
                if (m != null && m.toLowerCase().contains("refused")) return true;
            } catch (IOException ignored) { }
        }
        return false;
    }
}
