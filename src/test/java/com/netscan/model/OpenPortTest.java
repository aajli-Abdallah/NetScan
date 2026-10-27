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

package com.netscan.model;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class OpenPortTest {
    @Test void parsesAndNamesPorts() {
        assertThat(OpenPort.parse("22, 80,abc")).containsExactly(new OpenPort(22, "SSH"), new OpenPort(80, "HTTP"));
        assertThat(OpenPort.of(4242).service()).isEqualTo("unknown");
    }

    @Test void emptyInputGivesEmptyList() {
        assertThat(OpenPort.parse(null)).isEmpty();
        assertThat(OpenPort.parse("  ")).isEmpty();
    }

    @Test void formatsList() {
        assertThat(OpenPort.format(List.of(22, 443))).isEqualTo("22,443");
        assertThat(OpenPort.format(List.of())).isEmpty();
    }
}
