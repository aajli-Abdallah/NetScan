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

package com.netscan.backup;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.netscan.net.MacUtil;
import com.netscan.store.DeviceEntity;
import com.netscan.store.DeviceEventEntity;
import com.netscan.store.DeviceEventRepository;
import com.netscan.store.DeviceRepository;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.info.BuildProperties;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

/**
 * Backup = devices only (labels, known flags, ports). Events are history and are not in the backup (CSV export exists).
 * Merge rule: match by MAC, newest lastSeen wins, empty fields are filled, firstSeen = earliest, lastSeen = latest.
 */
@Service
public class BackupService {
    public static final int FORMAT = 1;

    public enum Mode {
        MERGE, REPLACE;

        public static Mode parse(String s) {
            if ("merge".equalsIgnoreCase(s)) return MERGE;
            if ("replace".equalsIgnoreCase(s)) return REPLACE;
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "mode must be merge or replace");
        }
    }

    public record Result(String mode, boolean applied, int created, int updated, int unchanged,
                         int removed, int skipped, List<String> warnings) {}

    record Merged(String label, boolean known, String vendor, String hostname, String lastIp,
                  Instant firstSeen, Instant lastSeen, String openPorts, Instant portsScannedAt) {
        boolean sameAs(DeviceEntity e) {
            return known == e.isKnown() && Objects.equals(label, e.getLabel()) && Objects.equals(vendor, e.getVendor())
                    && Objects.equals(hostname, e.getHostname()) && Objects.equals(lastIp, e.getLastIp())
                    && Objects.equals(firstSeen, e.getFirstSeen()) && Objects.equals(lastSeen, e.getLastSeen())
                    && Objects.equals(openPorts, e.getOpenPorts()) && Objects.equals(portsScannedAt, e.getPortsScannedAt());
        }

        void applyTo(DeviceEntity e) {
            e.setLabel(label); e.setKnown(known); e.setVendor(vendor); e.setHostname(hostname); e.setLastIp(lastIp);
            e.setFirstSeen(firstSeen); e.setLastSeen(lastSeen); e.setOpenPorts(openPorts); e.setPortsScannedAt(portsScannedAt);
        }
    }

    private final DeviceRepository repo;
    private final DeviceEventRepository events;
    private final ObjectProvider<BuildProperties> build;
    private final ObjectMapper mapper;
    private final Path dir;
    private final int keep;

    public BackupService(DeviceRepository repo, DeviceEventRepository events, ObjectProvider<BuildProperties> build,
                         ObjectMapper mapper, @Value("${netscan.backup.dir:./data/backups}") String dir,
                         @Value("${netscan.backup.keep:14}") int keep) {
        this.repo = repo;
        this.events = events;
        this.build = build;
        this.mapper = mapper;
        this.dir = Path.of(dir);
        this.keep = Math.max(1, keep);
    }

    public String appVersion() {
        BuildProperties b = build.getIfAvailable();
        return b == null ? "dev" : b.getVersion();
    }

    @Transactional(readOnly = true)
    public Backup export() {
        List<Backup.Dev> devs = repo.findAll(Sort.by("firstSeen")).stream().map(BackupService::toDev).toList();
        return new Backup(appVersion(), FORMAT, Instant.now(), devs);
    }

    @Transactional(readOnly = true)
    public String devicesCsv() {
        CsvWriter w = new CsvWriter().row("mac", "label", "known", "online", "vendor", "hostname", "lastIp",
                "firstSeen", "lastSeen", "openPorts");
        for (DeviceEntity e : repo.findAll(Sort.by("firstSeen")))
            w.row(e.getMac(), e.getLabel(), e.isKnown(), e.isOnline(), e.getVendor(), e.getHostname(), e.getLastIp(),
                    e.getFirstSeen(), e.getLastSeen(), e.getOpenPorts());
        return w.toString();
    }

    @Transactional(readOnly = true)
    public String eventsCsv() {
        CsvWriter w = new CsvWriter().row("time", "type", "mac", "label", "ip", "known");
        for (DeviceEventEntity e : events.findAllByOrderByOccurredAtDesc(PageRequest.of(0, 50_000)))
            w.row(e.getOccurredAt(), e.getType(), e.getMac(), e.getLabel(), e.getIp(), e.isKnown());
        return w.toString();
    }

    @Transactional
    public Result run(Backup raw, Mode mode, boolean apply) {
        Backup b = BackupUpgrader.upgrade(raw);
        List<String> warnings = new ArrayList<>();
        String current = appVersion();
        if (!"dev".equals(current) && Versions.compare(b.appVersion(), current) > 0)
            warnings.add("This backup was made by a newer NetScan (" + b.appVersion() + "). Unknown data is ignored.");

        Map<String, Backup.Dev> valid = new LinkedHashMap<>();
        Map<String, String> macs = new LinkedHashMap<>();
        int skipped = 0;
        for (Backup.Dev d : b.devices()) {
            String mac = d == null ? null : MacUtil.normalize(d.mac());
            if (mac == null || valid.containsKey(mac)) { skipped++; continue; }
            valid.put(mac, d);
        }
        Map<String, DeviceEntity> existing = repo.findAll().stream()
                .collect(Collectors.toMap(DeviceEntity::getMac, e -> e, (x, y) -> x));
        int created = 0, updated = 0, unchanged = 0, removed = 0;
        Instant now = Instant.now();

        if (mode == Mode.REPLACE) {
            for (String mac : valid.keySet()) if (existing.containsKey(mac)) updated++; else created++;
            for (String mac : existing.keySet()) if (!valid.containsKey(mac)) removed++;
            if (apply) {
                repo.deleteAllInBatch();
                Set<String> usedIds = new HashSet<>();
                List<DeviceEntity> list = new ArrayList<>();
                valid.forEach((mac, d) -> list.add(fresh(d, mac, usedIds, now)));
                repo.saveAll(list);
            }
        } else {
            Set<String> usedIds = existing.values().stream().map(DeviceEntity::getId).collect(Collectors.toSet());
            for (Map.Entry<String, Backup.Dev> en : valid.entrySet()) {
                DeviceEntity e = existing.get(en.getKey());
                if (e == null) {
                    created++;
                    if (apply) repo.save(fresh(en.getValue(), en.getKey(), usedIds, now));
                } else {
                    Merged m = merge(e, en.getValue());
                    if (m.sameAs(e)) unchanged++;
                    else {
                        updated++;
                        if (apply) { m.applyTo(e); repo.save(e); }
                    }
                }
            }
        }
        return new Result(mode.name().toLowerCase(), apply, created, updated, unchanged, removed, skipped, warnings);
    }

    static Merged merge(DeviceEntity e, Backup.Dev b) {
        boolean newer = b.lastSeen() != null && (e.getLastSeen() == null || b.lastSeen().isAfter(e.getLastSeen()));
        boolean portsNewer = b.portsScannedAt() != null
                && (e.getPortsScannedAt() == null || b.portsScannedAt().isAfter(e.getPortsScannedAt()));
        return new Merged(
                newer && has(b.label()) ? cut(b.label().trim(), 100) : e.getLabel() != null ? e.getLabel() : cut(nz(b.label()), 100),
                newer ? b.known() : e.isKnown(),
                e.getVendor() != null ? e.getVendor() : cut(nz(b.vendor()), 100),
                newer && has(b.hostname()) ? cut(b.hostname().trim(), 255) : e.getHostname() != null ? e.getHostname() : cut(nz(b.hostname()), 255),
                newer && has(b.lastIp()) ? cut(b.lastIp().trim(), 45) : e.getLastIp() != null ? e.getLastIp() : cut(nz(b.lastIp()), 45),
                earliest(e.getFirstSeen(), b.firstSeen()), latest(e.getLastSeen(), b.lastSeen()),
                portsNewer ? cut(nz(b.openPorts()), 255) : e.getOpenPorts(),
                portsNewer ? b.portsScannedAt() : e.getPortsScannedAt());
    }

    private static DeviceEntity fresh(Backup.Dev d, String mac, Set<String> usedIds, Instant now) {
        DeviceEntity e = new DeviceEntity();
        String id = d.id();
        if (id == null || id.isBlank() || id.length() > 36 || !usedIds.add(id)) {
            id = UUID.randomUUID().toString();
            usedIds.add(id);
        }
        e.setId(id);
        e.setMac(mac);
        e.setLabel(cut(nz(d.label()), 100));
        e.setKnown(d.known());
        e.setVendor(cut(nz(d.vendor()), 100));
        e.setHostname(cut(nz(d.hostname()), 255));
        e.setLastIp(cut(nz(d.lastIp()), 45));
        e.setFirstSeen(d.firstSeen() != null ? d.firstSeen() : d.lastSeen() != null ? d.lastSeen() : now);
        e.setLastSeen(d.lastSeen() != null ? d.lastSeen() : e.getFirstSeen());
        e.setOpenPorts(cut(nz(d.openPorts()), 255));
        e.setPortsScannedAt(d.portsScannedAt());
        return e;
    }

    static Backup.Dev toDev(DeviceEntity e) {
        return new Backup.Dev(e.getId(), e.getMac(), e.getLabel(), e.isKnown(), e.getVendor(), e.getHostname(),
                e.getLastIp(), e.getFirstSeen(), e.getLastSeen(), e.getOpenPorts(), e.getPortsScannedAt());
    }

    /** Writes today's backup file if it does not exist yet, then removes the oldest beyond the keep limit. */
    public Path ensureTodayBackup() throws IOException {
        Files.createDirectories(dir);
        Path f = dir.resolve("netscan-backup-" + LocalDate.now() + ".json");
        if (Files.exists(f)) return null;
        mapper.writerWithDefaultPrettyPrinter().writeValue(f.toFile(), export());
        try (var s = Files.list(dir)) {
            List<Path> all = s.filter(p -> p.getFileName().toString().startsWith("netscan-backup-")).sorted().toList();
            for (int i = 0; i < all.size() - keep; i++) Files.deleteIfExists(all.get(i));
        }
        return f;
    }

    private static boolean has(String s) { return s != null && !s.isBlank(); }
    private static String nz(String s) { return has(s) ? s.trim() : null; }
    private static String cut(String s, int max) { return s == null || s.length() <= max ? s : s.substring(0, max); }
    private static Instant earliest(Instant a, Instant b) { return a == null ? b : b == null ? a : a.isBefore(b) ? a : b; }
    private static Instant latest(Instant a, Instant b) { return a == null ? b : b == null ? a : a.isAfter(b) ? a : b; }
}
