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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.netscan.model.Device;
import com.netscan.net.OuiLookup;
import com.netscan.model.UpdateRequest;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

class DeviceStoreTest {
    static final String MAC = "AA:BB:CC:DD:EE:01";
    static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");
    static final Instant T1 = Instant.parse("2026-01-01T01:00:00Z");

    DeviceRepository repo = mock(DeviceRepository.class);
    DeviceEventRepository events = mock(DeviceEventRepository.class);
    DeviceStore store = new DeviceStore(repo, events, OuiLookup.seedOnly(), 2);

    @BeforeEach
    void setUp() {
        when(repo.save(any())).thenAnswer(i -> i.getArgument(0));
    }

    private void existing() {
        DeviceEntity e = new DeviceEntity();
        e.setId("id1");
        e.setMac(MAC);
        e.setFirstSeen(T0);
        e.setLastSeen(T0);
        e.setLastIp("192.168.1.5");
        when(repo.findByMac(MAC)).thenReturn(Optional.of(e));
        when(repo.findById("id1")).thenReturn(Optional.of(e));
    }

    @Test void newDeviceIsUnknown() {
        var v = store.sync(List.of(new Device("192.168.1.5", MAC, true, false)), T0).get(0);
        assertThat(v.known()).isFalse();
        assertThat(v.id()).isNotNull();
        assertThat(v.firstSeen()).isEqualTo(T0);
    }

    @Test void thisComputerIsKnown() {
        var v = store.sync(List.of(new Device("192.168.1.9", MAC, true, true)), T0).get(0);
        assertThat(v.known()).isTrue();
        assertThat(v.label()).isEqualTo("This computer");
    }

    @Test void reachableUpdatesLastSeenKeepsFirstSeen() {
        existing();
        var v = store.sync(List.of(new Device("192.168.1.7", MAC, true, false)), T1).get(0);
        assertThat(v.firstSeen()).isEqualTo(T0);
        assertThat(v.lastSeen()).isEqualTo(T1);
    }

    @Test void arpOnlyDeviceKeepsLastSeen() {
        existing();
        var v = store.sync(List.of(new Device("192.168.1.5", MAC, false, false)), T1).get(0);
        assertThat(v.lastSeen()).isEqualTo(T0);
    }

    @Test void deviceWithoutMacIsNotStored() {
        var v = store.sync(List.of(new Device("192.168.1.8", null, true, false)), T0).get(0);
        assertThat(v.id()).isNull();
        verify(repo, never()).save(any());
    }

    @Test void updateTrimsClearsAndValidatesLabel() {
        existing();
        assertThat(store.update("id1", new UpdateRequest("  TV  ", true)).label()).isEqualTo("TV");
        assertThat(store.update("id1", new UpdateRequest("   ", null)).label()).isNull();
        assertThrows(ResponseStatusException.class, () -> store.update("id1", new UpdateRequest("x".repeat(101), null)));
        assertThrows(ResponseStatusException.class, () -> store.update("nope", new UpdateRequest("a", null)));
    }
}
