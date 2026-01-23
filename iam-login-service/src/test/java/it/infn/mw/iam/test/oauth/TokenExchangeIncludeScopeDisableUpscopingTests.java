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
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.NoSuchElementException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import it.infn.mw.iam.core.oauth.exchange.DefaultTokenExchangePdp;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@SuppressWarnings("deprecation")
@ExtendWith(SpringExtension.class)
@IamMockMvcIntegrationTest
@TestPropertySource(properties = {"iam.access_token.include_scope=true"})
class TokenExchangeIncludeScopeDisableUpscopingTests extends EndpointsTestUtils {

    private static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";
    private static final String TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";

    private static final String TOKEN_ENDPOINT = "/token";

    private static final String ACTOR_CLIENT_ID = "token-exchange-actor";
    private static final String ACTOR_CLIENT_SECRET = "secret";

    private static final String SUBJECT_CLIENT_ID = "client-cred";
    private static final String SUBJECT_CLIENT_SECRET = "secret";

    private static final String ACTOR_CLIENT_ID_NO_OFFLINE = "token-lookup-client";
    private static final String ACTOR_CLIENT_SECRET_NO_OFFLINE = "secret";

    private static final String SUBJECT_CLIENT_ID_NO_OFFLINE = "post-client";
    private static final String SUBJECT_CLIENT_SECRET_NO_OFFLINE = "secret";


    private String accessToken;
    private ListAppender<ILoggingEvent> logCaptor;

    @Autowired
    private ObjectMapper mapper;

    @Autowired
    private IamClientRepository clientRepository;

    @BeforeEach
    void setup() throws Exception {

        logCaptor = attachLogCaptor(DefaultTokenExchangePdp.class);

        accessToken = new AccessTokenGetter().grantType("client_credentials")
            .clientId(SUBJECT_CLIENT_ID)
            .clientSecret(SUBJECT_CLIENT_SECRET)
            .scope("read-tasks")
            .getAccessTokenValue();

        ClientDetailsEntity client = clientRepository.findByClientId(ACTOR_CLIENT_ID)
            .orElseThrow(NoSuchElementException::new);
        client.setUpScopingEnabled(false);
        clientRepository.save(client);

        ClientDetailsEntity clientNoOffline =
                clientRepository.findByClientId(ACTOR_CLIENT_ID_NO_OFFLINE)
                    .orElseThrow(NoSuchElementException::new);
        clientNoOffline.getScope().remove("offline_access");
        clientNoOffline.setUpScopingEnabled(false);
        clientRepository.save(clientNoOffline);
    }

    // Upscoping disabled, Access token with scopes, same scopes, Scopes in token so no need for
    // token introspection
    @Test
    void testTokenExchangeSuccess() throws Exception {

        String tokenResponse = mvc
            .perform(post(TOKEN_ENDPOINT).with(httpBasic(ACTOR_CLIENT_ID, ACTOR_CLIENT_SECRET))
                .param("grant_type", GRANT_TYPE)
                .param("subject_token", accessToken)
                .param("subject_token_type", TOKEN_TYPE)
                .param("scope", "read-tasks"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.access_token").exists())
            .andExpect(jsonPath("$.scope", containsString("read-tasks")))
            .andReturn()
            .getResponse()
            .getContentAsString();

        DefaultOAuth2AccessToken tokenResponseObject =
                mapper.readValue(tokenResponse, DefaultOAuth2AccessToken.class);

        JWT exchangedToken = JWTParser.parse(tokenResponseObject.getValue());
        assertThat(exchangedToken.getJWTClaimsSet().getSubject(), is(SUBJECT_CLIENT_ID));

        // Scopes should be present in access token
        assertEquals("read-tasks", exchangedToken.getJWTClaimsSet().getClaim("scope"));

        // No token introspection used whilst doing the exchange
        boolean found = logCaptor.list.stream()
            .anyMatch(event -> event.getLevel() == Level.WARN && event.getFormattedMessage()
                .contains(
                        "Cannot verify requested scopes with subject token. Attempting token introspection instead."));

        assertFalse(found);
    }

    // Upscoping disabled, Access token with scopes, attempt at upscoping, Scopes in token so no
    // need for token introspection
    // 1. Upscoping fail - both actor and client has the scope, but upscoping isn't enabled
    // 2. Upscoping fail - subject missing the upscoping value
    // 3. Upscoping fail - actor missing the upscoping value
    @ParameterizedTest
    @CsvSource({"profile,scope not allowed by subject token configuration: profile",
            "email, scope not allowed by origin client configuration: email",
            "write-tasks, Scope 'write-tasks' not allowed for client 'token-exchange-actor'"})
    void testTokenExchangeUpScopingFail(String scope, String errorMessage) throws Exception {

        mvc.perform(post(TOKEN_ENDPOINT).with(httpBasic(ACTOR_CLIENT_ID, ACTOR_CLIENT_SECRET))
            .param("grant_type", GRANT_TYPE)
            .param("subject_token", accessToken)
            .param("subject_token_type", TOKEN_TYPE)
            .param("scope", scope))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").value("invalid_scope"))
            .andExpect(jsonPath("$.error_description").value(errorMessage));

        // No token introspection used whilst doing the exchange
        boolean found = logCaptor.list.stream()
            .anyMatch(event -> event.getLevel() == Level.WARN && event.getFormattedMessage()
                .contains(
                        "Cannot verify requested scopes with subject token. Attempting token introspection instead."));

        assertFalse(found);
    }

    // Upscoping disabled, Access token with scopes, Using upscoping in the exchange for offline
    // access, Scopes in token so no need for token introspection
    @Test
    void testTokenExchangeUpscopingOfflineAccessSuccess() throws Exception {

        String tokenResponse = mvc
            .perform(post(TOKEN_ENDPOINT).with(httpBasic(ACTOR_CLIENT_ID, ACTOR_CLIENT_SECRET))
                .param("grant_type", GRANT_TYPE)
                .param("subject_token", accessToken)
                .param("subject_token_type", TOKEN_TYPE)
                .param("scope", "read-tasks offline_access"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.access_token").exists())
            .andExpect(jsonPath("$.scope",
                    allOf(containsString("read-tasks"), containsString("offline_access"))))
            .andReturn()
            .getResponse()
            .getContentAsString();

        DefaultOAuth2AccessToken tokenResponseObject =
                mapper.readValue(tokenResponse, DefaultOAuth2AccessToken.class);

        JWT exchangedToken = JWTParser.parse(tokenResponseObject.getValue());
        assertThat(exchangedToken.getJWTClaimsSet().getSubject(), is(SUBJECT_CLIENT_ID));

        // Scopes should be present in access token
        assertThat((String) exchangedToken.getJWTClaimsSet().getClaim("scope"),
                containsString("offline_access"));
        assertThat((String) exchangedToken.getJWTClaimsSet().getClaim("scope"),
                containsString("read-tasks"));

        // No token introspection used whilst doing the exchange
        boolean found = logCaptor.list.stream()
            .anyMatch(event -> event.getLevel() == Level.WARN && event.getFormattedMessage()
                .contains(
                        "Cannot verify requested scopes with subject token. Attempting token introspection instead."));

        assertFalse(found);
    }

    // Token exchange, but only subject missing the requested offline_access scope
    @Test
    void testSubjectMissingOfflineScopeDuringExchangeFail() throws Exception {

        accessToken = new AccessTokenGetter().grantType("client_credentials")
            .clientId(SUBJECT_CLIENT_ID_NO_OFFLINE)
            .clientSecret(SUBJECT_CLIENT_SECRET_NO_OFFLINE)
            .scope("profile")
            .getAccessTokenValue();

        mvc.perform(post(TOKEN_ENDPOINT).with(httpBasic(ACTOR_CLIENT_ID, ACTOR_CLIENT_SECRET))
            .param("grant_type", GRANT_TYPE)
            .param("subject_token", accessToken)
            .param("subject_token_type", TOKEN_TYPE)
            .param("scope", "offline_access"))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").value("invalid_scope"))
            .andExpect(jsonPath("$.error_description")
                .value("scope not allowed by origin client configuration: offline_access"));

        // No token introspection used whilst doing the exchange
        boolean found = logCaptor.list.stream()
            .anyMatch(event -> event.getLevel() == Level.WARN && event.getFormattedMessage()
                .contains(
                        "Cannot verify requested scopes with subject token. Attempting token introspection instead."));

        // No need for token introspection, when scopes are present in token
        assertFalse(found);
    }

    // Token exchange, but only Actor missing the requested offline_access scope
    @Test
    void testActorMissingOfflineScopeDuringExchangeFail() throws Exception {

        mvc.perform(post(TOKEN_ENDPOINT)
            .with(httpBasic(ACTOR_CLIENT_ID_NO_OFFLINE, ACTOR_CLIENT_SECRET_NO_OFFLINE))
            .param("grant_type", GRANT_TYPE)
            .param("subject_token", accessToken)
            .param("subject_token_type", TOKEN_TYPE)
            .param("scope", "offline_access"))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").value("invalid_scope"))
            .andExpect(jsonPath("$.error_description")
                .value("Scope 'offline_access' not allowed for client 'token-lookup-client'"));

        // No token introspection used whilst doing the exchange
        boolean found = logCaptor.list.stream()
            .anyMatch(event -> event.getLevel() == Level.WARN && event.getFormattedMessage()
                .contains(
                        "Cannot verify requested scopes with subject token. Attempting token introspection instead."));

        // The error happens before it reaches this part
        assertFalse(found);
    }

    // Token exchange, Subject and Actor missing the offline scope
    @Test
    void testSubjectAndActorMissingOfflineScopeDuringExchangeFail() throws Exception {

        accessToken = new AccessTokenGetter().grantType("client_credentials")
            .clientId(SUBJECT_CLIENT_ID_NO_OFFLINE)
            .clientSecret(SUBJECT_CLIENT_SECRET_NO_OFFLINE)
            .scope("profile")
            .getAccessTokenValue();

        mvc.perform(post(TOKEN_ENDPOINT)
            .with(httpBasic(ACTOR_CLIENT_ID_NO_OFFLINE, ACTOR_CLIENT_SECRET_NO_OFFLINE))
            .param("grant_type", GRANT_TYPE)
            .param("subject_token", accessToken)
            .param("subject_token_type", TOKEN_TYPE)
            .param("scope", "offline_access"))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").value("invalid_scope"))
            .andExpect(jsonPath("$.error_description")
                .value("Scope 'offline_access' not allowed for client 'token-lookup-client'"));

        // No token introspection used whilst doing the exchange
        boolean found = logCaptor.list.stream()
            .anyMatch(event -> event.getLevel() == Level.WARN && event.getFormattedMessage()
                .contains(
                        "Cannot verify requested scopes with subject token. Attempting token introspection instead."));

        // The error happens before it reaches this part
        assertFalse(found);
    }
}
