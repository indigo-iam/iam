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
package it.infn.mw.iam.config;

import java.sql.Connection;
import java.time.Duration;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.sql.DataSource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.caffeine.CaffeineCache;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.core.web.wellknown.IamWellKnownInfoProvider;

@Component
@ConditionalOnProperty(name = "cache.database-monitor-enabled", havingValue = "true", matchIfMissing = false)
public class DatabaseMonitorCachePersistence {

    private static final Logger LOG = LoggerFactory.getLogger(DatabaseMonitorCachePersistence.class);
    private static final Duration PROBE_TIMEOUT = Duration.ofSeconds(5);

    private final DataSource dataSource;
    private final DatabaseAvailability availability;
    private final CacheManager cacheManager;
    private final long wellKnownTtlSecs;
    private final long checkIntervalMs;
    private final Duration probeTimeout;

    // One reusable daemon thread for every probe to not hold up other tasks
    private final ExecutorService probeExecutor = Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "database-availability-probe");
        thread.setDaemon(true);
        return thread;
    });

    // Own thread executor to not get interference or interfer with tasks
    private final ScheduledExecutorService monitorExecutor = Executors.newSingleThreadScheduledExecutor(runnable -> {
        Thread thread = new Thread(runnable, "database-availability-monitor");
        thread.setDaemon(true);
        return thread;
    });

    @PostConstruct
    void start() {
        monitorExecutor.scheduleWithFixedDelay(this::checkSafely, checkIntervalMs, checkIntervalMs,
                TimeUnit.MILLISECONDS);
    }

    // true if the monitor is actively probing
    private final AtomicBoolean probing = new AtomicBoolean(false);

    @Autowired
    public DatabaseMonitorCachePersistence(DataSource dataSource, DatabaseAvailability availability,
            CacheManager cacheManager, CacheProperties cacheProps) {
        this(dataSource, availability, cacheManager, cacheProps, PROBE_TIMEOUT);
    }

    // Private constructor as interval check is static
    private DatabaseMonitorCachePersistence(DataSource dataSource, DatabaseAvailability availability,
            CacheManager cacheManager, CacheProperties cacheProps, Duration probeTimeout) {
        this.dataSource = dataSource;
        this.availability = availability;
        this.cacheManager = cacheManager;
        this.wellKnownTtlSecs = cacheProps.getwellKnownCleanupPeriodSecs();
        this.checkIntervalMs = Long.parseLong(cacheProps.getdatabaseAvailabilityCheckInterval());
        this.probeTimeout = probeTimeout;
    }

    @PreDestroy
    void shutdown() {
        monitorExecutor.shutdownNow();
        probeExecutor.shutdownNow();
    }

    // A plain ScheduledExecutorService silently cancels all future runs after one
    // uncaught exception, to cope for the lack of Scheduled
    private void checkSafely() {
        try {
            checkDatabaseConnection();
        } catch (RuntimeException e) {
            LOG.warn("Database availability check failed unexpectedly", e);
        }
    }

    @Scheduled(fixedDelayString = "${cache.database-availability-check-interval}")
    public void checkDatabaseConnection() {
        // Call probe method to check current availability
        boolean up = probe();

        // If the DB is available as before, then don't do anything
        if (up == availability.isAvailable()) {
            return;
        }

        // Otherwise set the new value
        availability.set(up);

        if (up) {
            LOG.info("Database recovered: well-known cache entries get their normal lifetime back");
            setWellKnownLifetime(wellKnownTtlSecs, TimeUnit.SECONDS);
        } else {
            LOG.warn("Database unavailable: well-known cache entries are kept until it recovers");
            setWellKnownLifetime(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
        }
    }

    private boolean probe() {

        // Check if the last probe is still active
        if (!probing.compareAndSet(false, true)) {
            // the previous probe never returned: the database is not answering
            return false;
        }
        Future<Boolean> result;
        // Attempting the database check
        try {
            result = probeExecutor.submit(() -> {
                try (Connection connection = dataSource.getConnection()) {
                    return connection.isValid(2);
                } finally {
                    probing.set(false);
                }
            });

            // Unexpected error to start the job leads to database not classified as
            // available
        } catch (RejectedExecutionException e) {
            probing.set(false);
            return availability.isAvailable();
        }

        // Try to retrieve the result of the job within the time constraint
        try {
            return result.get(probeTimeout.toMillis(), TimeUnit.MILLISECONDS);

            // Failed cause the job took too long
        } catch (TimeoutException e) {
            result.cancel(true);
            LOG.debug("Database probe did not complete within {}", probeTimeout);
            return false;

            // The probe failed for some unknown error explain if using debug
        } catch (ExecutionException e) {
            LOG.debug("Database probe failed: {}", String.valueOf(e.getCause()));
            return false;

            // The probe failed as the thread was interrupted
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return availability.isAvailable();
        }
    }

    private void setWellKnownLifetime(long duration, TimeUnit unit) {
        Cache cache = cacheManager.getCache(IamWellKnownInfoProvider.CACHE_KEY);

        // Only handling the local cache and not redis cache
        if (!(cache instanceof CaffeineCache caffeine)) {
            return;
        }
        com.github.benmanes.caffeine.cache.Cache<Object, Object> nativeCache = caffeine.getNativeCache();
        nativeCache.policy().expireVariably().ifPresent(
                policy -> nativeCache.asMap().keySet().forEach(key -> policy.setExpiresAfter(key, duration, unit)));
    }
}
