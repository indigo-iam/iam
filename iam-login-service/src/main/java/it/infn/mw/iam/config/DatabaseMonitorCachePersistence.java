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
import java.sql.SQLException;
import java.util.concurrent.TimeUnit;

import javax.sql.DataSource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.caffeine.CaffeineCache;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.core.web.wellknown.IamWellKnownInfoProvider;

@EnableScheduling 
@Component
public class DatabaseMonitorCachePersistence {

    private static final Logger LOG = LoggerFactory.getLogger(DatabaseMonitorCachePersistence.class);

    private final DataSource dataSource;
    private final DatabaseAvailability availability;
    private final CacheManager cacheManager;
    private final long wellKnownTtlSecs;

    public DatabaseMonitorCachePersistence(DataSource dataSource, DatabaseAvailability availability,
            CacheManager cacheManager, CacheProperties cacheProps) {
        this.dataSource = dataSource;
        this.availability = availability;
        this.cacheManager = cacheManager;
        this.wellKnownTtlSecs = cacheProps.getwellKnownCleanupPeriodSecs();
    }

    @Scheduled(fixedDelayString = "${cache.database-availability-check-interval}")
    public void checkDatabaseConnection() {
        boolean up;
        try (Connection connection = dataSource.getConnection()) {
            up = connection.isValid(2);
        } catch (SQLException e) {
            up = false;
        }
        
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
