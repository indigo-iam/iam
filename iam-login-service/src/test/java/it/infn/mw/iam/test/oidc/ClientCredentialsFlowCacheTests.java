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
package it.infn.mw.iam.test.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.cache.CacheManager;
import org.springframework.cache.interceptor.SimpleKey;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.JsonNode;

import it.infn.mw.iam.api.client.service.DefaultClientService;
import it.infn.mw.iam.core.oauth.scope.IamSystemScopeService;
import it.infn.mw.iam.persistence.repository.IamScopeRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.test.util.oidc.OidcMockMvcTestSupport;

@SuppressWarnings("deprecation")
@Transactional
public class ClientCredentialsFlowCacheTests extends OidcMockMvcTestSupport {

    @SpyBean
    private DefaultClientService clientService;

    @SpyBean
    private IamSystemScopeService systemScopeService;

    @SpyBean
    private IamClientRepository clientRepository;

    @SpyBean
    private IamScopeRepository scopeRepository;

    @SpyBean(name = "iamClientDetailsService")
    private ClientDetailsService clientDetailsService;

    @Autowired
    private CacheManager cacheManager;

    @BeforeEach
    void clearCache() {
        cacheManager.getCache(DefaultClientService.CACHE_NAME).clear();
        cacheManager.getCache(IamSystemScopeService.CACHE_NAME).clear();
    }

    @Test
    void clientCredentialsSuccess() throws Exception {

        // First we assume that both caches are clean
        assertNull(cacheManager.getCache(IamSystemScopeService.CACHE_NAME).get(SimpleKey.EMPTY));
        assertNull(cacheManager.getCache(DefaultClientService.CACHE_NAME).get(CLIENT_CREDENTIALS_CLIENT_ID));

        JsonNode json = assert200AndParse(
                postForm(TOKEN_ENDPOINT, Map.of("grant_type", "client_credentials", "scope", "openid"),
                        CLIENT_CREDENTIALS_CLIENT_ID, CLIENT_CREDENTIALS_CLIENT_SECRET));

        assertTrue(json.has("access_token"));
        assertEquals("Bearer", json.get("token_type").asText());
        assertEquals("openid", json.get("scope").asText());

        // After the client credentials request, the client used should be in the cache
        assertNotNull(cacheManager.getCache(DefaultClientService.CACHE_NAME).get(CLIENT_CREDENTIALS_CLIENT_ID));

        // And the system scopes is also populated
        assertNotNull(cacheManager.getCache(IamSystemScopeService.CACHE_NAME).get(SimpleKey.EMPTY));

        // Verifying that each lookup is only called once
        // Any more than 1 means that the cache is broken
        verify(clientService, times(1))
                .findClientByClientId(CLIENT_CREDENTIALS_CLIENT_ID);

        verify(systemScopeService, times(1))
                .getAllUnSorted();

        // and the the clientDetailsService has not been called
        verify(clientDetailsService, times(0))
                .loadClientByClientId(CLIENT_CREDENTIALS_CLIENT_ID);


        // Also verifying that someone hasn't by passed the service
        // and just calls the repository directly
        verify(clientRepository, times(1)).findByClientId(CLIENT_CREDENTIALS_CLIENT_ID);
        verify(scopeRepository, times(1)).findAll();
    }
}
