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
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** TCP connect scan of a short port list. Only called on request, never from the scheduler. */
@Component
public class PortScanner {
    private final int timeoutMs;
    private final int[] ports;

    public PortScanner(@Value("${netscan.portscan-timeout-ms:500}") int timeoutMs,
                       @Value("${netscan.quick-ports:21,22,23,53,80,139,443,445,554,631,1883,3389,5900,8080,8443,9100}") int[] ports) {
        this.timeoutMs = timeoutMs;
        this.ports = ports;
    }

    public List<Integer> scan(String ip) {
        Set<Integer> open = ConcurrentHashMap.newKeySet();
        try (ExecutorService ex = Executors.newVirtualThreadPerTaskExecutor()) {
            for (int port : ports) {
                ex.submit(() -> {
                    try (Socket s = new Socket()) {
                        s.connect(new InetSocketAddress(ip, port), timeoutMs);
                        open.add(port);
                    } catch (IOException ignored) { }
                });
            }
        }
        return open.stream().sorted().toList();
    }
}
