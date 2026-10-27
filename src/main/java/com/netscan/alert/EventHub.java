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

package com.netscan.alert;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

/** Holds the open browser streams and pushes named events to all of them. */
@Component
public class EventHub {
    private final List<SseEmitter> emitters = new CopyOnWriteArrayList<>();

    public SseEmitter subscribe() {
        SseEmitter em = new SseEmitter(0L);
        emitters.add(em);
        em.onCompletion(() -> emitters.remove(em));
        em.onTimeout(() -> emitters.remove(em));
        em.onError(e -> emitters.remove(em));
        try {
            em.send(SseEmitter.event().name("hello").data("ok"));
        } catch (IOException e) {
            emitters.remove(em);
        }
        return em;
    }

    public void publish(String name, Object data) {
        for (SseEmitter em : emitters) {
            try {
                em.send(SseEmitter.event().name(name).data(data, MediaType.APPLICATION_JSON));
            } catch (Exception e) {
                emitters.remove(em);
            }
        }
    }
}
