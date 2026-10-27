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

package com.netscan.web;

import com.netscan.model.SavedDevice;
import com.netscan.model.UpdateRequest;
import com.netscan.scan.PortScanner;
import com.netscan.store.DeviceStore;
import java.time.Instant;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/saved")
public class SavedDeviceController {
    private final DeviceStore store;
    private final PortScanner portScanner;

    public SavedDeviceController(DeviceStore store, PortScanner portScanner) {
        this.store = store;
        this.portScanner = portScanner;
    }

    @GetMapping
    public List<SavedDevice> list(@RequestParam(required = false) Boolean known) {
        return store.saved(known);
    }

    @PatchMapping("/{id}")
    public SavedDevice update(@PathVariable String id, @RequestBody UpdateRequest req) {
        return store.update(id, req);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable String id) {
        store.delete(id);
    }

    /** Scans only an address NetScan itself recorded, only on request, only if the device is online. */
    @PostMapping("/{id}/portscan")
    public SavedDevice portScan(@PathVariable String id) {
        SavedDevice d = store.get(id);
        if (!d.online() || d.lastIp() == null)
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Device is offline; a port scan needs an online device");
        return store.recordPorts(id, portScanner.scan(d.lastIp()), Instant.now());
    }
}
