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

import java.util.List;

public interface ArpParser {
    String IP = "\\d{1,3}(?:\\.\\d{1,3}){3}";

    List<ArpEntry> parse(String raw);
}
