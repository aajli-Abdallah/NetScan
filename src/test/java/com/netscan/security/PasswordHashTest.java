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

package com.netscan.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

class PasswordHashTest {
    PasswordEncoder enc = PasswordEncoderFactories.createDelegatingPasswordEncoder();

    @Test void configuredPasswordWins(@TempDir Path dir) {
        String h = SecurityConfig.resolveHash("admin", "secret-1", dir.resolve("h"), enc);
        assertThat(enc.matches("secret-1", h)).isTrue();
        assertThat(Files.exists(dir.resolve("h"))).isFalse();
    }

    @Test void generatedHashIsStoredAndReused(@TempDir Path dir) {
        Path f = dir.resolve("sub").resolve("admin.hash");
        String first = SecurityConfig.resolveHash("admin", "", f, enc);
        assertThat(Files.exists(f)).isTrue();
        assertThat(SecurityConfig.resolveHash("admin", "", f, enc)).isEqualTo(first);
    }

    @Test void generatedPasswordsAreLongAndDifferent() {
        assertThat(SecurityConfig.generatePassword()).hasSize(16).isNotEqualTo(SecurityConfig.generatePassword());
    }
}
