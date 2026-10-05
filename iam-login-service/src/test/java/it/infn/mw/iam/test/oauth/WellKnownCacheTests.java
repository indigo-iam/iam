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
package it.infn.mw.iam.test.oauth;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.interceptor.SimpleKey;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.client.RestTemplate;

import it.infn.mw.iam.core.oauth.scope.SystemScopeService;
import it.infn.mw.iam.persistence.model.SystemScope;
import it.infn.mw.iam.core.web.wellknown.IamDiscoveryEndpoint;
import it.infn.mw.iam.core.web.wellknown.IamWellKnownInfoProvider;

import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.Matchers.hasItem;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;

@SpringBootTest(properties = { "cache.enabled=true", "cache.redis.enabled=false" })
@AutoConfigureMockMvc
@TestPropertySource(properties = "cache.well-known-cleanup-period-secs=1")
@EnableCaching
public class WellKnownCacheTests {

    protected static final String REMOTE_ISSUER = "https://example.com";
    protected static final String URL = REMOTE_ISSUER + "/.well-known/openid-configuration";

    private String endpoint = "/" + IamDiscoveryEndpoint.OPENID_CONFIGURATION_URL;

    private static final String SYSTEM_SCOPE_0 = "new-scope0";
    private static final String SYSTEM_SCOPE_1 = "new-scope1";

    @Autowired
    private MockMvc mvc;

    @Autowired
    private SystemScopeService scopeService;

    @MockBean
    private RestTemplate restTemplate;

    @Autowired
    private CacheManager cacheManager;

    @BeforeEach
    void clearCache() {
        cacheManager.getCache(IamWellKnownInfoProvider.CACHE_KEY).clear();
        assertNull(cacheManager.getCache(IamWellKnownInfoProvider.CACHE_KEY).get(SimpleKey.EMPTY));
    }

    @Test
    void testWellKnownCachePopulationAndEviction() throws Exception {

        // Before being populated:
        assertNull(cacheManager.getCache(IamWellKnownInfoProvider.CACHE_KEY).get(SimpleKey.EMPTY));

        SystemScope scope = new SystemScope(SYSTEM_SCOPE_0);
        scopeService.create(scope);

        mvc.perform(get(endpoint))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.scopes_supported").exists())
                .andExpect(jsonPath("$.scopes_supported").isArray())
                .andExpect(jsonPath("$.scopes_supported", hasItem(SYSTEM_SCOPE_0)));

        // After being populated:
        assertNotNull(
                cacheManager.getCache(IamWellKnownInfoProvider.CACHE_KEY).get(SimpleKey.EMPTY));

        scope = new SystemScope(SYSTEM_SCOPE_1);
        scopeService.create(scope);

        // Still getting the cached value, i.e. not updated
        mvc.perform(get(endpoint))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.scopes_supported").exists())
                .andExpect(jsonPath("$.scopes_supported").isArray())
                .andExpect(jsonPath("$.scopes_supported", hasItem(SYSTEM_SCOPE_0)))
                .andExpect(jsonPath("$.scopes_supported", not(SYSTEM_SCOPE_1)));

        // Emphasizing it's the cached used
        assertNotNull(
                cacheManager.getCache(IamWellKnownInfoProvider.CACHE_KEY).get(SimpleKey.EMPTY));

        // Waiting for the cache to expire
        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
            // empty catch
        }

        // Verifying the cache has expired
        assertNull(cacheManager.getCache(IamWellKnownInfoProvider.CACHE_KEY).get(SimpleKey.EMPTY));

        // Calling endpoint and verifying the values are updated
        mvc.perform(get(endpoint))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.scopes_supported").exists())
                .andExpect(jsonPath("$.scopes_supported").isArray())
                .andExpect(jsonPath("$.scopes_supported", hasItem(SYSTEM_SCOPE_0)))
                .andExpect(jsonPath("$.scopes_supported", hasItem(SYSTEM_SCOPE_1)));
    }
}
