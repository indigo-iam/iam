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
package it.infn.mw.iam.test.oauth.scope;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cache.CacheManager;
import org.springframework.cache.interceptor.SimpleKey;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.core.oauth.scope.IamSystemScopeService;
import it.infn.mw.iam.core.oauth.scope.SystemScopeService;
import it.infn.mw.iam.persistence.model.SystemScope;

import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;

@SpringBootTest(properties = { "cache.enabled=true", "cache.redis.enabled=false",
        "cache.default-cleanup-period-secs=1" })
@AutoConfigureMockMvc
@Transactional
public class SystemScopesCacheTests {

    private final String NEW_SCOPE = "Some-scope";
    private final String NEW_SCOPE_DESCRIPTION = "Some-scope-description";

    @Autowired
    private SystemScopeService scopeService;

    @Autowired
    private CacheManager cacheManager;

    @BeforeEach
    void clearCache() {
        cacheManager.getCache(IamSystemScopeService.CACHE_NAME).clear();
        assertNull(cacheManager.getCache(IamSystemScopeService.CACHE_NAME).get(SimpleKey.EMPTY));
    }

    private void waitForCacheExpiration() {
        long timeoutNanos = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);

        while (System.nanoTime() < timeoutNanos) {
            if (cacheManager.getCache(IamSystemScopeService.CACHE_NAME)
                    .get(SimpleKey.EMPTY) == null) {
                return;
            }
            LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(100));
        }
        assertNull(
                cacheManager.getCache(IamSystemScopeService.CACHE_NAME)
                        .get(SimpleKey.EMPTY));
    }

    @Test
    void removeEvictTest() {

        // Before being populated
        assertNull(cacheManager.getCache(IamSystemScopeService.CACHE_NAME).get(SimpleKey.EMPTY));

        // Adding a system scope for later removal
        SystemScope scope = new SystemScope(NEW_SCOPE);
        scopeService.create(scope);
        assertNull(cacheManager.getCache(IamSystemScopeService.CACHE_NAME).get(SimpleKey.EMPTY));

        // Populating cache
        List<SystemScope> systemScopes = scopeService.getAllUnSorted();

        // Confirming cache is populated
        assertNotNull(
                cacheManager.getCache(IamSystemScopeService.CACHE_NAME).get(SimpleKey.EMPTY));
        assertEquals(29, systemScopes.size());

        // Evicting through removal
        scopeService.remove(scope);

        // Confirming eviction
        assertNull(cacheManager.getCache(IamSystemScopeService.CACHE_NAME).get(SimpleKey.EMPTY));
    }

    @Test
    void createEvictTest() {

        // Before being populated
        assertNull(cacheManager.getCache(IamSystemScopeService.CACHE_NAME).get(SimpleKey.EMPTY));

        // Populating cache
        List<SystemScope> systemScopes = scopeService.getAllUnSorted();

        // Confirming cache is populated
        assertNotNull(
                cacheManager.getCache(IamSystemScopeService.CACHE_NAME).get(SimpleKey.EMPTY));
        assertEquals(28, systemScopes.size());

        // Evicting through creation of new scope
        SystemScope scope = new SystemScope(NEW_SCOPE);
        scopeService.create(scope);
        assertNull(cacheManager.getCache(IamSystemScopeService.CACHE_NAME).get(SimpleKey.EMPTY));
    }

    @Test
    void updateEvictTest() {
        // Before being populated
        assertNull(cacheManager.getCache(IamSystemScopeService.CACHE_NAME).get(SimpleKey.EMPTY));

        // Adding a system scope for later update
        SystemScope scope = new SystemScope(NEW_SCOPE);
        scopeService.create(scope);
        assertNull(cacheManager.getCache(IamSystemScopeService.CACHE_NAME).get(SimpleKey.EMPTY));

        // Populating cache
        List<SystemScope> systemScopes = scopeService.getAllUnSorted();

        // Confirming cache is populated
        assertNotNull(
                cacheManager.getCache(IamSystemScopeService.CACHE_NAME).get(SimpleKey.EMPTY));
        assertEquals(29, systemScopes.size());

        // Evicting the cache through update
        scope.setDescription(NEW_SCOPE_DESCRIPTION);
        scopeService.update(scope);

        // Confirming eviction
        assertNull(cacheManager.getCache(IamSystemScopeService.CACHE_NAME).get(SimpleKey.EMPTY));
    }

    @Test
    void getAllUnSortedPopulateTest() {
        // Before being populated
        assertNull(cacheManager.getCache(IamSystemScopeService.CACHE_NAME).get(SimpleKey.EMPTY));

        // Populating cache
        List<SystemScope> systemScopes = scopeService.getAllUnSorted();

        // Confirming cache is populated
        assertNotNull(
                cacheManager.getCache(IamSystemScopeService.CACHE_NAME).get(SimpleKey.EMPTY));
        assertEquals(28, systemScopes.size());
    }

    @Test
    void timeEvictTest() {
        // Before being populated
        assertNull(cacheManager.getCache(IamSystemScopeService.CACHE_NAME).get(SimpleKey.EMPTY));

        // Populating cache
        List<SystemScope> systemScopes = scopeService.getAllUnSorted();

        // Confirming cache is populated
        assertNotNull(
                cacheManager.getCache(IamSystemScopeService.CACHE_NAME).get(SimpleKey.EMPTY));
        assertEquals(28, systemScopes.size());

        waitForCacheExpiration();

        // Checking cache is evicted
        assertNull(cacheManager.getCache(IamSystemScopeService.CACHE_NAME).get(SimpleKey.EMPTY));
    }

    @Test
    void testSystemScopesCachePopulationAndEviction() {

        // Before being populated
        assertNull(cacheManager.getCache(IamSystemScopeService.CACHE_NAME).get(SimpleKey.EMPTY));

        // Populating cache
        List<SystemScope> systemScopes = scopeService.getAllUnSorted();

        // Confirming cache is populated
        assertNotNull(
                cacheManager.getCache(IamSystemScopeService.CACHE_NAME).get(SimpleKey.EMPTY));
        assertEquals(28, systemScopes.size());

        // Confirming time constraint eviction
        waitForCacheExpiration();

        // Checking cache is evicted
        assertNull(cacheManager.getCache(IamSystemScopeService.CACHE_NAME).get(SimpleKey.EMPTY));

        // Repopulating the cache
        systemScopes = scopeService.getAllUnSorted();

        // Confirming cache is populated
        assertNotNull(
                cacheManager.getCache(IamSystemScopeService.CACHE_NAME).get(SimpleKey.EMPTY));
        assertEquals(28, systemScopes.size());

        // Evicting the cache by creating a new scope
        SystemScope scope = new SystemScope(NEW_SCOPE);
        scopeService.create(scope);

        // Confirming eviction
        assertNull(cacheManager.getCache(IamSystemScopeService.CACHE_NAME).get(SimpleKey.EMPTY));

        // Repopulating the cache
        systemScopes = scopeService.getAllUnSorted();
        assertNotNull(
                cacheManager.getCache(IamSystemScopeService.CACHE_NAME).get(SimpleKey.EMPTY));
        assertEquals(29, systemScopes.size());
        assertTrue(systemScopes.contains(scope));
        assertNotEquals(systemScopes.get(systemScopes.indexOf(scope)).getDescription(), NEW_SCOPE_DESCRIPTION);

        // Evicting the cache through update
        scope.setDescription(NEW_SCOPE_DESCRIPTION);
        scopeService.update(scope);

        // Confirming eviction
        assertNull(cacheManager.getCache(IamSystemScopeService.CACHE_NAME).get(SimpleKey.EMPTY));

        // Repopulating the cache
        systemScopes = scopeService.getAllUnSorted();
        assertNotNull(
                cacheManager.getCache(IamSystemScopeService.CACHE_NAME).get(SimpleKey.EMPTY));
        assertEquals(29, systemScopes.size());
        assertTrue(systemScopes.contains(scope));
        assertEquals(systemScopes.get(systemScopes.indexOf(scope)).getDescription(), NEW_SCOPE_DESCRIPTION);

        // Evicting through removal
        scopeService.remove(scope);

        // Confirming eviction
        assertNull(cacheManager.getCache(IamSystemScopeService.CACHE_NAME).get(SimpleKey.EMPTY));

        // Cache miss with method that doesn't trigger the cache
        scopeService.getAllSorted();

        // Confirming the cache wasn't populated
        assertNull(cacheManager.getCache(IamSystemScopeService.CACHE_NAME).get(SimpleKey.EMPTY));
    }
}
