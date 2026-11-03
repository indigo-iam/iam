/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2021
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package it.infn.mw.iam.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.ServerSocket;
import java.sql.SQLException;
import java.time.Duration;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;
import java.util.function.BooleanSupplier;

import org.h2.tools.Server;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.caffeine.CaffeineCache;
import org.springframework.cache.interceptor.SimpleKey;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.DirtiesContext.ClassMode;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.config.CacheProperties;
import it.infn.mw.iam.config.DatabaseAvailability;
import it.infn.mw.iam.core.web.wellknown.IamWellKnownInfoProvider;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@IamMockMvcIntegrationTest
@DirtiesContext(classMode = ClassMode.AFTER_CLASS)
@TestPropertySource(properties = {
        "cache.enabled=true",
        "cache.redis.enabled=false",
        "cache.well-known-cleanup-period-secs=5",
        "cache.database-availability-check-interval=250",
        "spring.profiles.active=h2-test" })
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class DatabaseMonitorCacheTests {

    private static final String WELL_KNOWN = "/.well-known/openid-configuration";
    private static final long TTL_SECS = 5;

    private static final int DB_PORT = freePort();
    private static Server database;

    @Autowired
    private MockMvc mvc;
    @Autowired
    private CacheManager cacheManager;
    @Autowired
    private DatabaseAvailability availability;
    @Autowired
    private CacheProperties cacheProps;

    @DynamicPropertySource
    static void databaseProperties(DynamicPropertyRegistry registry) throws Exception {
        database = startDatabase();
        // Tcp connection so it can be stopped at will
        registry.add("spring.datasource.url", () -> "jdbc:h2:tcp://localhost:" + DB_PORT
                + "/mem:wellknowncache;DB_CLOSE_ON_EXIT=FALSE;DB_CLOSE_DELAY=-1;MODE=LEGACY;NON_KEYWORDS=VALUE");
    }

    @AfterAll
    static void stopDatabase() {
        if (database != null) {
            database.stop();
        }
    }

    @Test
    void wellKnownCacheSurvivesDatabaseOutageAndExpiresAgainAfterRecovery() throws Exception {

        assertEquals(TTL_SECS, cacheProps.getwellKnownCleanupPeriodSecs(),
                "the test property did not reach CacheProperties: check its key");
        Cache wellKnownCache = cacheManager.getCache(IamWellKnownInfoProvider.CACHE_KEY);
        assertInstanceOf(CaffeineCache.class, wellKnownCache);

        // Checking it serves the well-known and cache is present
        mvc.perform(get(WELL_KNOWN)).andExpect(status().isOk());
        assertNotNull(wellKnownCache.get(SimpleKey.EMPTY), "entry should be cached after the first request");
        assertTrue(availability.isAvailable());

        // Stop database and check the db monitor registered it
        database.stop();
        await("the monitor to notice the outage", Duration.ofSeconds(15), () -> !availability.isAvailable());

        // Wait until cache should have expired and verify it persists
        LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(TTL_SECS * 1000 + 2000L));
        assertNotNull(wellKnownCache.get(SimpleKey.EMPTY), "entry must not be evicted during the outage");
        mvc.perform(get(WELL_KNOWN)).andExpect(status().isOk());

        // Restarting DB and check monitor notices
        database = startDatabase();
        await("the monitor to notice the recovery", Duration.ofSeconds(15), availability::isAvailable);

        // Check that eviction happens as normal
        LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(TTL_SECS * 1000 + 2000L));
        assertNull(wellKnownCache.get(SimpleKey.EMPTY), "entry should expire normally after the recovery");
    }

    private static Server startDatabase() throws SQLException {
        return Server.createTcpServer("-tcpPort", String.valueOf(DB_PORT), "-ifNotExists").start();
    }

    private static void await(String what, Duration timeout, BooleanSupplier condition) {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                fail("Timed out waiting for " + what);
            }
            LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(100L));
        }
    }

    private static int freePort() {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}