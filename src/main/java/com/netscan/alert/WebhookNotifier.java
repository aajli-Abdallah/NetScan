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

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Optional push (ntfy, Discord, Telegram, Slack). Off when no URL is set. Never blocks or throws. */
@Component
public class WebhookNotifier {
    private static final Logger log = LoggerFactory.getLogger(WebhookNotifier.class);
    private final String url;
    private final String format;
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    public WebhookNotifier(@Value("${netscan.alert.webhook-url:}") String url,
                           @Value("${netscan.alert.webhook-format:text}") String format) {
        this.url = url == null ? "" : url.trim();
        this.format = format;
    }

    public boolean enabled() {
        return !url.isEmpty();
    }

    public void send(String message) {
        if (!enabled()) return;
        Thread.startVirtualThread(() -> {
            try {
                boolean text = body(format, "x").equals("x");
                HttpRequest req = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(10))
                        .header("Content-Type", text ? "text/plain; charset=utf-8" : "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body(format, message))).build();
                HttpResponse<Void> r = client.send(req, HttpResponse.BodyHandlers.discarding());
                if (r.statusCode() >= 300) log.warn("Webhook answered HTTP {}", r.statusCode());
            } catch (Exception e) {
                log.warn("Webhook failed: {}", e.toString());
            }
        });
    }

    static String body(String format, String message) {
        String f = format == null ? "text" : format.trim().toLowerCase();
        if (f.equals("discord")) return "{\"content\":" + jsonString(message) + "}";
        if (f.equals("telegram") || f.equals("slack")) return "{\"text\":" + jsonString(message) + "}";
        return message;
    }

    static String jsonString(String s) {
        StringBuilder sb = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
                }
            }
        }
        return sb.append('"').toString();
    }
}
