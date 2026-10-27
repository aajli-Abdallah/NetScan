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

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

/** Whole application on in-memory H2: wiring, Flyway, security and the import round trip. */
@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:h2:mem:sectest;DB_CLOSE_DELAY=-1",
        "netscan.scheduler.enabled=false",
        "netscan.backup.enabled=false",
        "netscan.security.password=test-pass-123"})
@AutoConfigureMockMvc
class SecurityAndImportTest {
    @Autowired MockMvc mvc;

    static final String BODY = "{\"appVersion\":\"1.0.0\",\"devices\":[{\"mac\":\"AA:BB:CC:DD:EE:01\",\"label\":\"TV\",\"known\":true}]}";

    @Test void anonymousIsRedirectedToLogin() throws Exception {
        mvc.perform(get("/api/info")).andExpect(status().is3xxRedirection());
    }

    @Test void loginPageIsPublic() throws Exception {
        mvc.perform(get("/login")).andExpect(status().isOk());
    }

    @Test void signedInCanReadInfo() throws Exception {
        mvc.perform(get("/api/info").with(user("admin"))).andExpect(status().isOk());
    }

    @Test void postWithoutCsrfIsForbidden() throws Exception {
        mvc.perform(post("/api/alerts/test").with(user("admin"))).andExpect(status().isForbidden());
    }

    @Test void postWithCsrfWorks() throws Exception {
        mvc.perform(post("/api/alerts/test").with(user("admin")).with(csrf())).andExpect(status().isOk());
    }

    @Test void importPreviewApplyAndUnchanged() throws Exception {
        mvc.perform(post("/api/import/preview?mode=merge").with(user("admin")).with(csrf())
                .contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isOk()).andExpect(jsonPath("$.created").value(1)).andExpect(jsonPath("$.applied").value(false));
        mvc.perform(post("/api/import?mode=merge").with(user("admin")).with(csrf())
                .contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isOk()).andExpect(jsonPath("$.created").value(1)).andExpect(jsonPath("$.applied").value(true));
        mvc.perform(post("/api/import/preview?mode=merge").with(user("admin")).with(csrf())
                .contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isOk()).andExpect(jsonPath("$.unchanged").value(1));
        mvc.perform(get("/api/export/backup.json").with(user("admin")))
                .andExpect(status().isOk()).andExpect(jsonPath("$.format").value(1)).andExpect(jsonPath("$.devices[0].label").value("TV"));
    }

    @Test void badModeIsRejected() throws Exception {
        mvc.perform(post("/api/import/preview?mode=wipe").with(user("admin")).with(csrf())
                .contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isBadRequest());
    }
}
