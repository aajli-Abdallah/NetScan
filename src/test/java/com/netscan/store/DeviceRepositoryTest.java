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

package com.netscan.store;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

/** Runs Flyway + schema validation against in-memory H2: catches migration/entity mismatches. */
@DataJpaTest
class DeviceRepositoryTest {
    @Autowired DeviceRepository repo;

    @Test void savesAndFindsByMac() {
        DeviceEntity e = new DeviceEntity();
        e.setId(UUID.randomUUID().toString());
        e.setMac("AA:BB:CC:DD:EE:01");
        e.setFirstSeen(Instant.now());
        e.setLastSeen(Instant.now());
        repo.saveAndFlush(e);
        assertThat(repo.findByMac("AA:BB:CC:DD:EE:01")).isPresent();
        assertThat(repo.findByMac("AA:BB:CC:DD:EE:02")).isEmpty();
    }
}
