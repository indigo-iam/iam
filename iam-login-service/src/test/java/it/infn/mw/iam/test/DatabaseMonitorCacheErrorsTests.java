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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.LockSupport;
import java.util.function.BooleanSupplier;

import javax.sql.DataSource;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.cache.CacheManager;

import it.infn.mw.iam.config.CacheProperties;
import it.infn.mw.iam.config.DatabaseAvailability;
import it.infn.mw.iam.config.DatabaseMonitorCachePersistence;

public class DatabaseMonitorCacheErrorsTests {

    private final DatabaseAvailability availability = new DatabaseAvailability();
    private final DataSource dataSource = mock(DataSource.class);
    private final CacheManager cacheManager = mock(CacheManager.class);
    private final CacheProperties props = new CacheProperties();

    private DatabaseMonitorCachePersistence monitor;

    @BeforeEach
    void setUp() {
        // New monitor each test
        monitor = new DatabaseMonitorCachePersistence(dataSource, availability, cacheManager, props);
    }

    @AfterEach
    void tearDown() {
        monitor.shutdown();
    }

    // ExecutionException branch

    @Test
    void failingConnectionIsTreatedAsDownAndReleasesTheProbeSlot() throws Exception {
        when(dataSource.getConnection()).thenThrow(new SQLException("refused"));

        monitor.checkDatabaseConnection();
        assertFalse(availability.isAvailable());

        monitor.checkDatabaseConnection();
        // Should have checked once for each time, as the probe should have been freed
        // up
        verify(dataSource, times(2)).getConnection();
    }

    @Test
    void unexpectedExceptionIsTreatedAsDown() throws Exception {
        when(dataSource.getConnection()).thenThrow(new IllegalStateException("huh, that was odd"));

        monitor.checkDatabaseConnection();

        assertFalse(availability.isAvailable());
    }

    // TimeoutException branch, probe that ignores interrupts

    @Test
    void hangingConnectionTimesOutOnlyOneProbeIsInFlightAndRecoveryIsDetectedLater() throws Exception {
        Connection ok = validConnection();
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger calls = new AtomicInteger();
        when(dataSource.getConnection()).thenAnswer(invocation -> {
            if (calls.incrementAndGet() == 1) {
                while (release.getCount() > 0) {
                    try {
                        release.await();
                    } catch (InterruptedException ignored) {
                        // mimics a driver connect that ignores interrupts
                    }
                }
            }
            return ok;
        });

        // gives up after 5 seconds
        monitor.checkDatabaseConnection();
        assertFalse(availability.isAvailable());
        assertEquals(1, calls.get());

        monitor.checkDatabaseConnection(); // the stuck probe still holds the slot
        assertEquals(1, calls.get(), "no second probe may be queued behind the stuck one");

        release.countDown(); // the driver finally returns
        await(Duration.ofSeconds(5), () -> {
            monitor.checkDatabaseConnection();
            return availability.isAvailable();
        });
        assertEquals(2, calls.get());
    }

    // TimeoutException branch, probe that reacts to cancel(true)

    @Test
    void interruptibleHangIsCancelledAndTheNextCheckProbesAgain() throws Exception {
        Connection ok = validConnection();
        CountDownLatch never = new CountDownLatch(1);
        AtomicInteger calls = new AtomicInteger();
        when(dataSource.getConnection()).thenAnswer(invocation -> {
            if (calls.incrementAndGet() == 1) {
                try {
                    never.await();
                } catch (InterruptedException e) {
                    throw new SQLException("interrupted", e);
                }
            }
            return ok;
        });

        // Runs out of time
        monitor.checkDatabaseConnection();
        assertFalse(availability.isAvailable());

        await(Duration.ofSeconds(5), () -> {
            monitor.checkDatabaseConnection();
            return availability.isAvailable();
        });
        assertEquals(2, calls.get());
    }

    // RejectedExecutionException branch

    @Test
    void checkAfterShutdownKeepsTheStateAndNeverTouchesTheDatabase() {
        monitor.shutdown();

        monitor.checkDatabaseConnection();

        assertTrue(availability.isAvailable());
        verifyNoInteractions(dataSource);
    }

    // InterruptedException branch

    @Test
    void interruptedWhileWaitingKeepsTheStateAndRestoresTheInterruptFlag() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        when(dataSource.getConnection()).thenAnswer(invocation -> {
            release.await();
            throw new SQLException("released");
        });

        Thread.currentThread().interrupt();
        try {
            monitor.checkDatabaseConnection();
            assertTrue(Thread.currentThread().isInterrupted(), "interrupt flag must be restored");
            assertTrue(availability.isAvailable(), "shutting down must not change the state");
        } finally {
            // Makes sure to close this thread to not leak into other tests
            Thread.interrupted();
            release.countDown();
        }
    }

    // checkSafely: RuntimeException branch

    @Test
    void loopSurvivesAnExceptionThrownByTheTransitionLogic() throws Exception {
        props.setdatabaseAvailabilityCheckInterval("50");
        DatabaseMonitorCachePersistence looping = new DatabaseMonitorCachePersistence(dataSource,
                availability, cacheManager, props);
        Connection ok = validConnection();
        AtomicBoolean databaseUp = new AtomicBoolean(true);
        when(dataSource.getConnection()).thenAnswer(invocation -> {
            if (databaseUp.get()) {
                return ok;
            }
            throw new SQLException("down");
        });
        when(cacheManager.getCache(anyString()))
                .thenThrow(new IllegalStateException("a really odd error, that I don't know what is"));

        looping.start();
        try {
            databaseUp.set(false);
            // First call throws the error
            verify(cacheManager, timeout(3000).atLeast(1)).getCache(anyString()); 
            databaseUp.set(true);
            // The monitor is still running despite the error 
            verify(cacheManager, timeout(3000).atLeast(2)).getCache(anyString()); 
        } finally {
            looping.shutdown();
        }
    }

    private Connection validConnection() throws SQLException {
        Connection connection = mock(Connection.class);
        when(connection.isValid(anyInt())).thenReturn(true);
        return connection;
    }

    private static void await(Duration timeout, BooleanSupplier condition) throws InterruptedException {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                fail("Timed out");
            }
            LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(50L));
        }
    }

}
