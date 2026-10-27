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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.netscan.model.Device;
import com.netscan.net.OuiLookup;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class DeviceStoreChangeTest {
    static final Instant T = Instant.parse("2026-01-01T00:00:00Z");
    static final String MAC = "AA:BB:CC:DD:EE:01";

    DeviceRepository repo = mock(DeviceRepository.class);
    DeviceEventRepository events = mock(DeviceEventRepository.class);
    DeviceStore store = new DeviceStore(repo, events, OuiLookup.seedOnly(), 2);
    DeviceEntity dev = new DeviceEntity();
    List<Device> miss = List.of(new Device("192.168.1.5", MAC, false, false));
    List<Device> hit = List.of(new Device("192.168.1.5", MAC, true, false));

    @BeforeEach
    void setUp() {
        dev.setId("id1");
        dev.setMac(MAC);
        dev.setFirstSeen(T);
        dev.setLastSeen(T);
        dev.setOnline(true);
        when(repo.save(any())).thenAnswer(i -> i.getArgument(0));
        when(repo.findByMac(MAC)).thenReturn(Optional.of(dev));
        when(repo.findByOnlineTrue()).thenAnswer(i -> dev.isOnline() ? List.of(dev) : List.of());
    }

    private List<String> types() {
        ArgumentCaptor<DeviceEventEntity> c = ArgumentCaptor.forClass(DeviceEventEntity.class);
        verify(events, atLeast(0)).save(c.capture());
        return c.getAllValues().stream().map(DeviceEventEntity::getType).toList();
    }

    @Test void goesOfflineOnlyAfterTwoMisses() {
        store.sync(miss, T);
        assertThat(dev.isOnline()).isTrue();
        assertThat(types()).isEmpty();
        store.sync(miss, T);
        assertThat(dev.isOnline()).isFalse();
        assertThat(types()).containsExactly("OFFLINE");
    }

    @Test void deviceMissingFromScanCountsAsMiss() {
        store.sync(List.of(), T);
        store.sync(List.of(), T);
        assertThat(dev.isOnline()).isFalse();
    }

    @Test void reachableResetsMisses() {
        store.sync(miss, T);
        store.sync(hit, T);
        store.sync(miss, T);
        assertThat(dev.isOnline()).isTrue();
    }

    @Test void comesBackOnline() {
        dev.setOnline(false);
        dev.setMissed(5);
        store.sync(hit, T);
        assertThat(dev.isOnline()).isTrue();
        assertThat(dev.getMissed()).isZero();
        assertThat(types()).containsExactly("ONLINE");
    }

    @Test void newDeviceRecordsJoined() {
        store.sync(List.of(new Device("192.168.1.9", "AA:BB:CC:DD:EE:09", true, false)), T);
        assertThat(types()).containsExactly("JOINED");
    }
}
