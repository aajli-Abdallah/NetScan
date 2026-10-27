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

import static org.assertj.core.api.Assertions.assertThat;

import java.net.InetAddress;
import java.net.ServerSocket;
import org.junit.jupiter.api.Test;

class PortScannerTest {
    @Test void findsOnlyTheOpenPort() throws Exception {
        try (ServerSocket ss = new ServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
            int open = ss.getLocalPort();
            PortScanner scanner = new PortScanner(500, new int[]{open, 1});
            assertThat(scanner.scan("127.0.0.1")).containsExactly(open);
        }
    }
}
