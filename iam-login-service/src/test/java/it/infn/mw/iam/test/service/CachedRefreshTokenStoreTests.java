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
package it.infn.mw.iam.test.service;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;

import org.springframework.cache.CacheManager;

import it.infn.mw.iam.persistence.model.OAuth2RefreshTokenEntity;
import it.infn.mw.iam.api.tokens.service.CachedRefreshTokenStore;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;
import org.webjars.NotFoundException;

@SpringBootTest(properties = { "cache.enabled=true", "cache.redis.enabled=false",
        "cache.default-cleanup-period-secs=1" })
@Transactional
public class CachedRefreshTokenStoreTests {

    private final String TOKEN_1 = "first-token";
    private final String TOKEN_2 = "second-token";

    @Autowired
    private CachedRefreshTokenStore refreshTokenStore;

    @Autowired
    private CacheManager cacheManager;

    private void waitForCacheExpiration() {
        long timeoutNanos = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);

        while (System.nanoTime() < timeoutNanos) {
            if (cacheManager.getCache(CachedRefreshTokenStore.CACHE_NAME)
                    .get(TOKEN_1) == null) {
                return;
            }
            LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(100));
        }
        assertNull(cacheManager.getCache(CachedRefreshTokenStore.CACHE_NAME).get(TOKEN_1));
    }

    @BeforeEach
    void clearCache() {
        cacheManager.getCache(CachedRefreshTokenStore.CACHE_NAME).clear();
    }

    @Test
    void getTokenPopulatesCacheTest() {

        // Checking that token 1 isn't in the cache
        assertNull(cacheManager.getCache(CachedRefreshTokenStore.CACHE_NAME).get(TOKEN_1));

        // Creating Token 1 and saving it
        OAuth2RefreshTokenEntity refreshToken1 = new OAuth2RefreshTokenEntity();
        refreshToken1.setValue(TOKEN_1);
        refreshTokenStore.save(refreshToken1);
        assertNull(cacheManager.getCache(CachedRefreshTokenStore.CACHE_NAME).get(TOKEN_1));

        // Then populating the cache with token 1
        refreshToken1 = refreshTokenStore.getToken(TOKEN_1)
                .orElseThrow(() -> new NotFoundException("Token should be present"));
        assertEquals(TOKEN_1, refreshToken1.getValue());

        // Confirming token 1 is in the cache
        assertNotNull(cacheManager.getCache(CachedRefreshTokenStore.CACHE_NAME).get(TOKEN_1));
    }

    @Test
    void saveTokenEvictsCacheTest() {

        // Checking that token 1 isn't in the cache
        assertNull(cacheManager.getCache(CachedRefreshTokenStore.CACHE_NAME).get(TOKEN_1));

        // Creating Token 1 and saving it
        OAuth2RefreshTokenEntity refreshToken1 = new OAuth2RefreshTokenEntity();
        refreshToken1.setValue(TOKEN_1);
        refreshTokenStore.save(refreshToken1);
        assertNull(cacheManager.getCache(CachedRefreshTokenStore.CACHE_NAME).get(TOKEN_1));

        // Then populating the cache with token 1
        refreshToken1 = refreshTokenStore.getToken(TOKEN_1)
                .orElseThrow(() -> new NotFoundException("Token should be present"));
        assertEquals(TOKEN_1, refreshToken1.getValue());

        // Confirming token 1 is in the cache
        assertNotNull(cacheManager.getCache(CachedRefreshTokenStore.CACHE_NAME).get(TOKEN_1));

        // Evicting token 1 by saving it
        refreshTokenStore.save(refreshToken1);
        assertNull(cacheManager.getCache(CachedRefreshTokenStore.CACHE_NAME).get(TOKEN_1));
    }

    @Test
    void cachedTokenExpiresTest() {
        // Checking that token 1 isn't in the cache
        assertNull(cacheManager.getCache(CachedRefreshTokenStore.CACHE_NAME).get(TOKEN_1));

        // Creating Token 1 and saving it
        OAuth2RefreshTokenEntity refreshToken1 = new OAuth2RefreshTokenEntity();
        refreshToken1.setValue(TOKEN_1);
        refreshTokenStore.save(refreshToken1);
        assertNull(cacheManager.getCache(CachedRefreshTokenStore.CACHE_NAME).get(TOKEN_1));

        // Then populating the cache with token 1
        refreshToken1 = refreshTokenStore.getToken(TOKEN_1)
                .orElseThrow(() -> new NotFoundException("Token should be present"));
        assertEquals(TOKEN_1, refreshToken1.getValue());

        waitForCacheExpiration();

        // Confirming token 1 has been evicted
        assertNull(cacheManager.getCache(CachedRefreshTokenStore.CACHE_NAME).get(TOKEN_1));
    }

    @Test
    void evictAllTest() {

        // Creating Token 1 and saving it
        OAuth2RefreshTokenEntity refreshToken1 = new OAuth2RefreshTokenEntity();
        refreshToken1.setValue(TOKEN_1);
        refreshTokenStore.save(refreshToken1);
        assertNull(cacheManager.getCache(CachedRefreshTokenStore.CACHE_NAME).get(TOKEN_1));

        // Creating Token 2 and saving it
        OAuth2RefreshTokenEntity refreshToken2 = new OAuth2RefreshTokenEntity();
        refreshToken2.setValue(TOKEN_2);
        refreshTokenStore.save(refreshToken2);
        assertNull(cacheManager.getCache(CachedRefreshTokenStore.CACHE_NAME).get(TOKEN_2));

        // Fetching both tokens to put them in the cache
        refreshToken1 = refreshTokenStore.getToken(TOKEN_1)
                .orElseThrow(() -> new NotFoundException("Token should be present"));
        refreshToken2 = refreshTokenStore.getToken(TOKEN_2)
                .orElseThrow(() -> new NotFoundException("Token should be present"));
        assertEquals(TOKEN_1, refreshToken1.getValue());
        assertEquals(TOKEN_2, refreshToken2.getValue());
        assertNotNull(cacheManager.getCache(CachedRefreshTokenStore.CACHE_NAME).get(TOKEN_1));
        assertNotNull(cacheManager.getCache(CachedRefreshTokenStore.CACHE_NAME).get(TOKEN_2));

        // Evicting all tokens
        List<OAuth2RefreshTokenEntity> tokens = Arrays.asList(refreshToken1, refreshToken2);
        refreshTokenStore.evictAll(tokens);

        // Confirming both tokens are evicted
        assertNull(cacheManager.getCache(CachedRefreshTokenStore.CACHE_NAME).get(TOKEN_1));
        assertNull(cacheManager.getCache(CachedRefreshTokenStore.CACHE_NAME).get(TOKEN_2));
    }

    @Test
    void deleteEvictsTest() {

        // Checking that token 1 isn't in the cache
        assertNull(cacheManager.getCache(CachedRefreshTokenStore.CACHE_NAME).get(TOKEN_1));

        // Creating Token 1 and saving it
        OAuth2RefreshTokenEntity refreshToken1 = new OAuth2RefreshTokenEntity();
        refreshToken1.setValue(TOKEN_1);
        refreshTokenStore.save(refreshToken1);
        assertNull(cacheManager.getCache(CachedRefreshTokenStore.CACHE_NAME).get(TOKEN_1));

        // Then populating the cache with token 1
        refreshToken1 = refreshTokenStore.getToken(TOKEN_1)
                .orElseThrow(() -> new NotFoundException("Token should be present"));
        assertEquals(TOKEN_1, refreshToken1.getValue());

        // Confirming token 1 is in the cache
        assertNotNull(cacheManager.getCache(CachedRefreshTokenStore.CACHE_NAME).get(TOKEN_1));

        // Evicting token 1 by deleting it
        refreshTokenStore.delete(refreshToken1);
        assertNull(cacheManager.getCache(CachedRefreshTokenStore.CACHE_NAME).get(TOKEN_1));

    }

    @Test
    void testCachedRefreshTokenStorePopulationAndEviction() {

        // Checking that the tokens aren't in the cache
        assertNull(cacheManager.getCache(CachedRefreshTokenStore.CACHE_NAME).get(TOKEN_1));
        assertNull(cacheManager.getCache(CachedRefreshTokenStore.CACHE_NAME).get(TOKEN_2));

        // Creating Token 1 and saving it
        OAuth2RefreshTokenEntity refreshToken1 = new OAuth2RefreshTokenEntity();
        refreshToken1.setValue(TOKEN_1);
        refreshTokenStore.save(refreshToken1);
        assertNull(cacheManager.getCache(CachedRefreshTokenStore.CACHE_NAME).get(TOKEN_1));

        // Then populating the cache with token 1
        refreshToken1 = refreshTokenStore.getToken(TOKEN_1)
                .orElseThrow(() -> new NotFoundException("Token should be present"));
        assertEquals(TOKEN_1, refreshToken1.getValue());

        // Confirming token 1 is in the cache
        assertNotNull(cacheManager.getCache(CachedRefreshTokenStore.CACHE_NAME).get(TOKEN_1));

        waitForCacheExpiration();

        // Confirming token 1 has been evicted
        assertNull(cacheManager.getCache(CachedRefreshTokenStore.CACHE_NAME).get(TOKEN_1));

        // Creating Token 2 and saving it
        OAuth2RefreshTokenEntity refreshToken2 = new OAuth2RefreshTokenEntity();
        refreshToken2.setValue(TOKEN_2);
        refreshTokenStore.save(refreshToken2);
        assertNull(cacheManager.getCache(CachedRefreshTokenStore.CACHE_NAME).get(TOKEN_2));

        // Fetching both tokens to put them in the cache
        refreshToken1 = refreshTokenStore.getToken(TOKEN_1)
                .orElseThrow(() -> new NotFoundException("Token should be present"));
        refreshToken2 = refreshTokenStore.getToken(TOKEN_2)
                .orElseThrow(() -> new NotFoundException("Token should be present"));
        assertEquals(TOKEN_1, refreshToken1.getValue());
        assertEquals(TOKEN_2, refreshToken2.getValue());
        assertNotNull(cacheManager.getCache(CachedRefreshTokenStore.CACHE_NAME).get(TOKEN_1));
        assertNotNull(cacheManager.getCache(CachedRefreshTokenStore.CACHE_NAME).get(TOKEN_2));

        // Evicting all tokens
        List<OAuth2RefreshTokenEntity> tokens = Arrays.asList(refreshToken1, refreshToken2);
        refreshTokenStore.evictAll(tokens);

        // Confirming both tokens are evicted
        assertNull(cacheManager.getCache(CachedRefreshTokenStore.CACHE_NAME).get(TOKEN_1));
        assertNull(cacheManager.getCache(CachedRefreshTokenStore.CACHE_NAME).get(TOKEN_2));

        // Fetching both tokens to put them in the cache
        refreshToken1 = refreshTokenStore.getToken(TOKEN_1)
                .orElseThrow(() -> new NotFoundException("Token should be present"));
        refreshToken2 = refreshTokenStore.getToken(TOKEN_2)
                .orElseThrow(() -> new NotFoundException("Token should be present"));
        assertEquals(TOKEN_1, refreshToken1.getValue());
        assertEquals(TOKEN_2, refreshToken2.getValue());
        assertNotNull(cacheManager.getCache(CachedRefreshTokenStore.CACHE_NAME).get(TOKEN_1));
        assertNotNull(cacheManager.getCache(CachedRefreshTokenStore.CACHE_NAME).get(TOKEN_2));

        // Evicting token 1 by saving it
        refreshTokenStore.save(refreshToken1);
        assertNull(cacheManager.getCache(CachedRefreshTokenStore.CACHE_NAME).get(TOKEN_1));

        // Evicting token 2 by deleting it
        refreshTokenStore.delete(refreshToken2);
        assertNull(cacheManager.getCache(CachedRefreshTokenStore.CACHE_NAME).get(TOKEN_2));
    }
}
