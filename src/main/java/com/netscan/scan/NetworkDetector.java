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

import com.netscan.model.NetworkInfo;
import com.netscan.net.Cidr;
import com.netscan.net.MacUtil;
import java.net.Inet4Address;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Enumeration;
import java.util.List;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/** Finds the first active private IPv4 interface that is not a VM/container adapter. */
@Component
public class NetworkDetector {
    private static final Logger log = LoggerFactory.getLogger(NetworkDetector.class);
    private static final List<String> VIRTUAL = List.of("docker", "veth", "vbox", "virtualbox",
            "vmware", "vethernet", "virbr", "br-", "tailscale", "hyper-v", "loopback");

    public Optional<NetworkInfo> detect() {
        try {
            Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces();
            while (en != null && en.hasMoreElements()) {
                NetworkInterface ni = en.nextElement();
                if (!ni.isUp() || ni.isLoopback() || ni.isVirtual() || looksVirtual(ni)) continue;
                for (InterfaceAddress ia : ni.getInterfaceAddresses()) {
                    if (ia.getAddress() instanceof Inet4Address a && a.isSiteLocalAddress()) {
                        int prefix = ia.getNetworkPrefixLength();
                        if (prefix < 1 || prefix > 30) continue;
                        String ip = a.getHostAddress();
                        byte[] hw = ni.getHardwareAddress();
                        return Optional.of(new NetworkInfo(ni.getName(), ip,
                                hw == null ? null : MacUtil.format(hw), prefix,
                                Cidr.of(ip, prefix).toString(),
                                Cidr.of(ip, Math.max(prefix, 24)).toString()));
                    }
                }
            }
        } catch (SocketException e) {
            log.warn("Interface scan failed: {}", e.toString());
        }
        return Optional.empty();
    }

    private boolean looksVirtual(NetworkInterface ni) {
        String s = (ni.getName() + " " + ni.getDisplayName()).toLowerCase();
        return VIRTUAL.stream().anyMatch(s::contains);
    }
}
