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

import com.netscan.model.Device;
import com.netscan.model.DeviceChanged;
import com.netscan.model.DeviceEvent;
import com.netscan.model.DeviceView;
import com.netscan.model.EventType;
import com.netscan.model.OpenPort;
import com.netscan.model.SavedDevice;
import com.netscan.model.UpdateRequest;
import com.netscan.net.OuiLookup;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class DeviceStore {
    private final DeviceRepository repo;
    private final DeviceEventRepository events;
    private final OuiLookup oui;
    private final int offlineAfterMisses;
    private ApplicationEventPublisher publisher;

    /** Optional: tests run without it. */
    @Autowired(required = false)
    void setPublisher(ApplicationEventPublisher publisher) {
        this.publisher = publisher;
    }

    public DeviceStore(DeviceRepository repo, DeviceEventRepository events, OuiLookup oui,
                       @Value("${netscan.offline-after-misses:2}") int offlineAfterMisses) {
        this.repo = repo;
        this.events = events;
        this.oui = oui;
        this.offlineAfterMisses = Math.max(1, offlineAfterMisses);
    }

    /**
     * Merge one scan into the database and record changes.
     * New MAC = JOINED (unknown, except this computer). Offline only after N missed scans.
     */
    @Transactional
    public List<DeviceView> sync(List<Device> scanned, Instant now) {
        List<DeviceView> out = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        boolean baseline = repo.count() == 0; // first scan ever: record, but do not alert
        for (Device d : scanned) {
            DeviceEntity e = null;
            if (d.mac() != null) {
                seen.add(d.mac());
                e = repo.findByMac(d.mac()).orElse(null);
                boolean created = e == null;
                if (created) {
                    e = new DeviceEntity();
                    e.setId(UUID.randomUUID().toString());
                    e.setMac(d.mac());
                    e.setFirstSeen(now);
                    e.setLastSeen(now);
                    e.setLastIp(d.ip());
                    e.setKnown(d.self());
                    if (d.self()) e.setLabel("This computer");
                    record(e, EventType.JOINED, now, !baseline);
                }
                if (e.getVendor() == null) e.setVendor(abbr(oui.lookup(e.getMac()), 100));
                if (d.reachable()) {
                    e.setLastSeen(now);
                    e.setLastIp(d.ip());
                    e.setMissed(0);
                    if (d.hostname() != null) e.setHostname(abbr(d.hostname(), 255));
                    if (!e.isOnline()) {
                        e.setOnline(true);
                        if (!created) record(e, EventType.ONLINE, now, true);
                    }
                } else if (!created) {
                    miss(e, now);
                }
                e = repo.save(e);
            }
            out.add(e == null
                    ? new DeviceView(null, d.ip(), null, null, d.hostname(), null, false, d.reachable(),
                            d.reachable(), d.self(), null, null)
                    : new DeviceView(e.getId(), d.ip(), e.getMac(), e.getLabel(), e.getHostname(), e.getVendor(),
                            e.isKnown(), e.isOnline(), d.reachable(), d.self(), e.getFirstSeen(), e.getLastSeen()));
        }
        // Online devices that did not show up at all in this scan also count as a miss.
        for (DeviceEntity e : repo.findByOnlineTrue()) {
            if (!seen.contains(e.getMac())) {
                miss(e, now);
                repo.save(e);
            }
        }
        return out;
    }

    private void miss(DeviceEntity e, Instant now) {
        e.setMissed(Math.min(e.getMissed() + 1, 1_000_000));
        if (e.isOnline() && e.getMissed() >= offlineAfterMisses) {
            e.setOnline(false);
            record(e, EventType.OFFLINE, now, true);
        }
    }

    private void record(DeviceEntity e, EventType type, Instant at, boolean notify) {
        DeviceEventEntity ev = events.save(DeviceEventEntity.of(e, type.name(), at));
        if (notify && publisher != null && ev != null) {
            publisher.publishEvent(new DeviceChanged(new DeviceEvent(ev.getId(), ev.getDeviceId(), ev.getMac(),
                    ev.getLabel(), ev.getIp(), ev.isKnown(), ev.getType(), ev.getOccurredAt())));
        }
    }

    private static String abbr(String s, int max) {
        return s == null || s.length() <= max ? s : s.substring(0, max);
    }

    @Transactional(readOnly = true)
    public List<SavedDevice> saved(Boolean known) {
        return repo.findAll(Sort.by(Sort.Direction.DESC, "lastSeen")).stream()
                .filter(e -> known == null || e.isKnown() == known)
                .map(DeviceStore::toSaved)
                .toList();
    }

    @Transactional(readOnly = true)
    public SavedDevice get(String id) {
        return toSaved(repo.findById(id).orElseThrow(DeviceStore::notFound));
    }

    @Transactional
    public SavedDevice recordPorts(String id, List<Integer> ports, Instant at) {
        DeviceEntity e = repo.findById(id).orElseThrow(DeviceStore::notFound);
        e.setOpenPorts(OpenPort.format(ports));
        e.setPortsScannedAt(at);
        return toSaved(repo.save(e));
    }

    @Transactional(readOnly = true)
    public List<DeviceEvent> events(String deviceId, int limit) {
        PageRequest page = PageRequest.of(0, Math.max(1, Math.min(limit, 500)));
        List<DeviceEventEntity> list = deviceId == null
                ? events.findAllByOrderByOccurredAtDesc(page)
                : events.findByDeviceIdOrderByOccurredAtDesc(deviceId, page);
        return list.stream()
                .map(e -> new DeviceEvent(e.getId(), e.getDeviceId(), e.getMac(), e.getLabel(), e.getIp(),
                        e.isKnown(), e.getType(), e.getOccurredAt()))
                .toList();
    }

    @Transactional
    public int purgeEvents(int olderThanDays) {
        return events.deleteOlderThan(Instant.now().minus(olderThanDays, ChronoUnit.DAYS));
    }

    @Transactional
    public SavedDevice update(String id, UpdateRequest req) {
        DeviceEntity e = repo.findById(id).orElseThrow(DeviceStore::notFound);
        if (req.label() != null) {
            String l = req.label().trim();
            if (l.length() > 100)
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Label must be 100 characters or less");
            e.setLabel(l.isEmpty() ? null : l);
        }
        if (req.known() != null) e.setKnown(req.known());
        return toSaved(repo.save(e));
    }

    @Transactional
    public void delete(String id) {
        if (!repo.existsById(id)) throw notFound();
        repo.deleteById(id);
    }

    private static ResponseStatusException notFound() {
        return new ResponseStatusException(HttpStatus.NOT_FOUND, "Device not found");
    }

    private static SavedDevice toSaved(DeviceEntity e) {
        return new SavedDevice(e.getId(), e.getMac(), e.getLastIp(), e.getLabel(), e.getHostname(), e.getVendor(),
                e.isKnown(), e.isOnline(), e.getFirstSeen(), e.getLastSeen(),
                OpenPort.parse(e.getOpenPorts()), e.getPortsScannedAt());
    }
}
