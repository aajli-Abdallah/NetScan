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

package com.netscan.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.filter.OncePerRequestFilter;

/** Single-user login. Everything (page, API, live stream) requires it. */
@Configuration
public class SecurityConfig {
    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    UserDetailsService users(PasswordEncoder enc,
                             @Value("${netscan.security.username:admin}") String user,
                             @Value("${netscan.security.password:}") String password,
                             @Value("${netscan.security.hash-file:./data/admin.hash}") String hashFile) {
        String hash = resolveHash(user, password, Path.of(hashFile), enc);
        return new InMemoryUserDetailsManager(User.withUsername(user).password(hash).roles("ADMIN").build());
    }

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(a -> a.anyRequest().authenticated())
            .formLogin(Customizer.withDefaults())
            .logout(Customizer.withDefaults())
            .csrf(c -> c.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                    .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler()))
            .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class);
        return http.build();
    }

    /** Configured password wins. Otherwise use the stored hash, or create a random password once. */
    static String resolveHash(String user, String configured, Path file, PasswordEncoder enc) {
        if (configured != null && !configured.isBlank()) return enc.encode(configured);
        try {
            if (Files.isRegularFile(file)) {
                String h = Files.readString(file).trim();
                if (!h.isEmpty()) return h;
            }
            String pw = generatePassword();
            String hash = enc.encode(pw);
            if (file.getParent() != null) Files.createDirectories(file.getParent());
            Files.writeString(file, hash);
            log.warn("FIRST RUN - sign in with user '{}' and password '{}'. Shown once. To reset, delete {}", user, pw, file);
            return hash;
        } catch (IOException e) {
            String pw = generatePassword();
            log.warn("Could not store the password hash ({}). Temporary password for this run: '{}'", e.toString(), pw);
            return enc.encode(pw);
        }
    }

    static String generatePassword() {
        String chars = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789";
        SecureRandom r = new SecureRandom();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 16; i++) sb.append(chars.charAt(r.nextInt(chars.length())));
        return sb.toString();
    }

    /** Makes sure the CSRF cookie is sent so the page can echo it in a header. */
    static final class CsrfCookieFilter extends OncePerRequestFilter {
        @Override
        protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
                throws ServletException, IOException {
            CsrfToken token = (CsrfToken) req.getAttribute("_csrf");
            if (token != null) token.getToken();
            chain.doFilter(req, res);
        }
    }
}
