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

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.cache.CacheManager;
import org.springframework.cache.interceptor.SimpleKey;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.client.service.DefaultClientService;
import it.infn.mw.iam.core.oauth.scope.IamSystemScopeService;
import it.infn.mw.iam.persistence.repository.IamScopeRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oidc.OidcMockMvcTestSupport;

@SuppressWarnings("deprecation")
@IamMockMvcIntegrationTest
@SpringBootTest(classes = { IamLoginService.class }, webEnvironment = WebEnvironment.MOCK, properties = {
                "iam.access_token.include_scope=true"})
public class TokenExchangeCacheTests extends OidcMockMvcTestSupport {

        private static final String TOKEN_ENDPOINT = "/token";

        @Autowired
        private ObjectMapper mapper;

        @SpyBean
        private DefaultClientService clientService;

        @SpyBean
        private IamSystemScopeService systemScopeService;

        @SpyBean
        private IamClientRepository clientRepository;

        @SpyBean
        private IamScopeRepository scopeRepository;

        @Autowired
        protected MockMvc mvc;

        @Autowired
        private CacheManager cacheManager;

        @BeforeEach
        void init() {
                cacheManager.getCache(DefaultClientService.CACHE_NAME).clear();
                cacheManager.getCache(IamSystemScopeService.CACHE_NAME).clear();
        }

        @Test
        void clientCredentialsSuccess() throws Exception {

                // First we assume that both caches are clean
                assertNull(cacheManager.getCache(IamSystemScopeService.CACHE_NAME).get(SimpleKey.EMPTY));

                // Have to check each client used
                assertNull(cacheManager.getCache(DefaultClientService.CACHE_NAME).get(CLIENT_CREDENTIALS_CLIENT_ID));
                assertNull(cacheManager.getCache(DefaultClientService.CACHE_NAME).get(EXCHANGE_CLIENT_ID));

                // Then fetch access token with client credentials
                JsonNode json = assert200AndParse(
                                postForm(TOKEN_ENDPOINT, Map.of("grant_type", "client_credentials", "scope", "openid"),
                                                CLIENT_CREDENTIALS_CLIENT_ID, CLIENT_CREDENTIALS_CLIENT_SECRET));

                assertTrue(json.has("access_token"));
                assertEquals("Bearer", json.get("token_type").asText());

                String accessToken = json.get("access_token").asText();

                // After the client credentials request, the client used should be in the cache
                assertNotNull(cacheManager.getCache(DefaultClientService.CACHE_NAME).get(CLIENT_CREDENTIALS_CLIENT_ID));

                // And the system scopes should also be within the cache
                assertNotNull(cacheManager.getCache(IamSystemScopeService.CACHE_NAME).get(SimpleKey.EMPTY));

                // Then use said accesstoken to do the token exchange
                String tokenResponse = mvc
                                .perform(post(TOKEN_ENDPOINT)
                                                .with(httpBasic(EXCHANGE_CLIENT_ID, EXCHANGE_CLIENT_SECRET))
                                                .param("grant_type", TOKEN_EXCHANGE_GRANT_TYPE)
                                                .param("subject_token", accessToken)
                                                .param("subject_token_type", TOKEN_TYPE_JWT)
                                                .param("scope", "offline_access"))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.access_token").exists())
                                .andExpect(jsonPath("$.refresh_token").exists())
                                .andExpect(jsonPath("$.scope", containsString("offline_access")))
                                .andReturn()
                                .getResponse()
                                .getContentAsString();

                DefaultOAuth2AccessToken tokenResponseObject = mapper.readValue(tokenResponse,
                                DefaultOAuth2AccessToken.class);

                JWT exchangedToken = JWTParser.parse(tokenResponseObject.getValue());
                assertThat(exchangedToken.getJWTClaimsSet().getSubject(), is(CLIENT_CREDENTIALS_CLIENT_ID));
                assertEquals("offline_access", exchangedToken.getJWTClaimsSet().getClaim("scope"));

                // After the token exchange, system scopes and both clients should be present in
                // the cache
                assertNotNull(cacheManager.getCache(IamSystemScopeService.CACHE_NAME).get(SimpleKey.EMPTY));
                assertNotNull(cacheManager.getCache(DefaultClientService.CACHE_NAME).get(CLIENT_CREDENTIALS_CLIENT_ID));
                assertNotNull(cacheManager.getCache(DefaultClientService.CACHE_NAME).get(EXCHANGE_CLIENT_ID));

                // Verifying that each lookup is only called once
                // Any more than 1 means that the cache is broken
                verify(clientService, times(1))
                                .findClientByClientId(CLIENT_CREDENTIALS_CLIENT_ID);

                verify(clientService, times(1))
                                .findClientByClientId(EXCHANGE_CLIENT_ID);

                verify(systemScopeService, times(1))
                                .getAllUnSorted();

                // Also verifying that someone hasn't by passed the service
                // and just calls the repository directly
                verify(clientRepository, times(1)).findByClientId(CLIENT_CREDENTIALS_CLIENT_ID);
                verify(clientRepository, times(1)).findByClientId(EXCHANGE_CLIENT_ID);
                verify(scopeRepository, times(1)).findAll();
        }
}
