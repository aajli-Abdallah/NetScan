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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.netscan.model.Device;
import com.netscan.model.DeviceChanged;
import com.netscan.net.OuiLookup;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEventPublisher;

class DeviceStoreAlertTest {
    static final Instant T = Instant.parse("2026-01-01T00:00:00Z");
    DeviceRepository repo = mock(DeviceRepository.class);
    DeviceEventRepository events = mock(DeviceEventRepository.class);
    ApplicationEventPublisher publisher = mock(ApplicationEventPublisher.class);
    DeviceStore store = new DeviceStore(repo, events, OuiLookup.seedOnly(), 2);
    List<Device> newDevice = List.of(new Device("192.168.1.9", "AA:BB:CC:DD:EE:09", true, false));

    @BeforeEach
    void setUp() {
        store.setPublisher(publisher);
        when(repo.save(any())).thenAnswer(i -> i.getArgument(0));
        when(events.save(any())).thenAnswer(i -> i.getArgument(0));
    }

    @Test void firstScanIsBaselineAndSilent() {
        when(repo.count()).thenReturn(0L);
        store.sync(newDevice, T);
        verify(publisher, never()).publishEvent(any(Object.class));
    }

    @Test void laterNewDevicePublishesJoinedUnknown() {
        when(repo.count()).thenReturn(3L);
        store.sync(newDevice, T);
        ArgumentCaptor<Object> c = ArgumentCaptor.forClass(Object.class);
        verify(publisher).publishEvent(c.capture());
        DeviceChanged ch = (DeviceChanged) c.getValue();
        assertThat(ch.event().type()).isEqualTo("JOINED");
        assertThat(ch.event().known()).isFalse();
    }
}
