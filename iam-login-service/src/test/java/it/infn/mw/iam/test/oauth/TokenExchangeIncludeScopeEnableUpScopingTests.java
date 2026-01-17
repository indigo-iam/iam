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
class TokenExchangeIncludeScopeEnableUpScopingTests extends EndpointsTestUtils {

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

        ClientDetailsEntity clientNoOffline =
                clientRepository.findByClientId(ACTOR_CLIENT_ID_NO_OFFLINE)
                    .orElseThrow(NoSuchElementException::new);
        clientNoOffline.getScope().remove("offline_access");
        clientRepository.save(clientNoOffline);
    }

    // Upscoping Enabled, Access token with scopes, no upscoping, No token introspection as there're
    // scopes in the token
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

    // Upscoping Enabled, Access token with scopes, using upscoping in exchange, No token
    // introspection as there're scopes in the token
    @Test
    void testTokenExchangeUpscopingSuccess() throws Exception {

        String tokenResponse = mvc
            .perform(post(TOKEN_ENDPOINT).with(httpBasic(ACTOR_CLIENT_ID, ACTOR_CLIENT_SECRET))
                .param("grant_type", GRANT_TYPE)
                .param("subject_token", accessToken)
                .param("subject_token_type", TOKEN_TYPE)
                .param("scope", "storage.read:/"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.access_token").exists())
            .andExpect(jsonPath("$.scope", containsString("storage.read:/")))
            .andReturn()
            .getResponse()
            .getContentAsString();

        DefaultOAuth2AccessToken tokenResponseObject =
                mapper.readValue(tokenResponse, DefaultOAuth2AccessToken.class);

        JWT exchangedToken = JWTParser.parse(tokenResponseObject.getValue());
        assertThat(exchangedToken.getJWTClaimsSet().getSubject(), is(SUBJECT_CLIENT_ID));

        // Scopes should be present in access token
        assertEquals("storage.read:/", exchangedToken.getJWTClaimsSet().getClaim("scope"));

        // No token introspection used whilst doing the exchange
        boolean found = logCaptor.list.stream()
            .anyMatch(event -> event.getLevel() == Level.WARN && event.getFormattedMessage()
                .contains(
                        "Cannot verify requested scopes with subject token. Attempting token introspection instead."));

        assertFalse(found);
    }

    // Upscoping Enabled, Access token without scopes, Using upscoping in the exchange for offline
    // access, No token introspection as there're scopes in the token
    @Test
    void testTokenExchangeUpscopingOfflineScope() throws Exception {

        String tokenResponse = mvc
            .perform(post(TOKEN_ENDPOINT).with(httpBasic(ACTOR_CLIENT_ID, ACTOR_CLIENT_SECRET))
                .param("grant_type", GRANT_TYPE)
                .param("subject_token", accessToken)
                .param("subject_token_type", TOKEN_TYPE)
                .param("scope", "read-tasks offline_access"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.access_token").exists())
            .andExpect(jsonPath("$.scope",
                    allOf(containsString("offline_access"), containsString("read-tasks"))))
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


    // Token Exchange, but only subject missing the scope requested
    @Test
    void testSubjectMissingScopeDuringExchangeFail() throws Exception {

        mvc.perform(post(TOKEN_ENDPOINT).with(httpBasic(ACTOR_CLIENT_ID, ACTOR_CLIENT_SECRET))
            .param("grant_type", GRANT_TYPE)
            .param("subject_token", accessToken)
            .param("subject_token_type", TOKEN_TYPE)
            .param("scope", "email"))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").value("invalid_scope"))
            .andExpect(jsonPath("$.error_description")
                .value("scope not allowed by origin client configuration: email"));

        // No token introspection used whilst doing the exchange
        boolean found = logCaptor.list.stream()
            .anyMatch(event -> event.getLevel() == Level.WARN && event.getFormattedMessage()
                .contains(
                        "Cannot verify requested scopes with subject token. Attempting token introspection instead."));

        assertFalse(found);
    }

    // Token exchange, but only actor missing the scope requested
    @Test
    void testActorMissingScopeDuringExchangeFail() throws Exception {

        mvc.perform(post(TOKEN_ENDPOINT).with(httpBasic(ACTOR_CLIENT_ID, ACTOR_CLIENT_SECRET))
            .param("grant_type", GRANT_TYPE)
            .param("subject_token", accessToken)
            .param("subject_token_type", TOKEN_TYPE)
            .param("scope", "write-tasks"))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").value("invalid_scope"))
            .andExpect(jsonPath("$.error_description")
                .value("Scope 'write-tasks' not allowed for client 'token-exchange-actor'"));

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

        assertFalse(found);
    }
}
