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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.core.oauth.exchange.DefaultTokenExchangePdp;

@SuppressWarnings("deprecation")
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Transactional
class TokenExchangeExcludeScopeEnableUpScopingTests extends EndpointsTestUtils {

  private String accessToken;
  private ListAppender<ILoggingEvent> logCaptor;

  @Autowired
  private ObjectMapper mapper;

  @BeforeEach
  void setup() throws Exception {

    logCaptor = attachLogCaptor(DefaultTokenExchangePdp.class);

    accessToken = new AccessTokenGetter().grantType(CLIENT_CREDENTIALS_GRANT_TYPE)
      .clientId(CLIENT_CREDENTIALS_CLIENT_ID)
      .clientSecret(CLIENT_CREDENTIALS_CLIENT_SECRET)
      .scope("read-tasks")
      .getAccessTokenValue();
  }

  @Test
  void testTokenExchangeSuccess() throws Exception {

    String tokenResponse = mvc
      .perform(post(TOKEN_ENDPOINT).with(httpBasic(EXCHANGE_CLIENT_ID, EXCHANGE_CLIENT_SECRET))
        .param("grant_type", TOKEN_EXCHANGE_GRANT_TYPE)
        .param("subject_token", accessToken)
        .param("subject_token_type", TOKEN_TYPE_JWT)
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
    assertThat(exchangedToken.getJWTClaimsSet().getSubject(), is(CLIENT_CREDENTIALS_CLIENT_ID));
  }

  @Test
  void testTokenExchangeUpScopingSuccess() throws Exception {

    String tokenResponse = mvc
      .perform(post(TOKEN_ENDPOINT).with(httpBasic(EXCHANGE_CLIENT_ID, EXCHANGE_CLIENT_SECRET))
        .param("grant_type", TOKEN_EXCHANGE_GRANT_TYPE)
        .param("subject_token", accessToken)
        .param("subject_token_type", TOKEN_TYPE_JWT)
        .param("scope", "profile"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.scope", containsString("profile")))
      .andReturn()
      .getResponse()
      .getContentAsString();

    DefaultOAuth2AccessToken tokenResponseObject =
        mapper.readValue(tokenResponse, DefaultOAuth2AccessToken.class);

    JWT exchangedToken = JWTParser.parse(tokenResponseObject.getValue());
    assertThat(exchangedToken.getJWTClaimsSet().getSubject(), is(CLIENT_CREDENTIALS_CLIENT_ID));
  }

  @Test
  void testTokenExchangeUpscopingOfflineAccessSuccess() throws Exception {

    String tokenResponse = mvc
      .perform(post(TOKEN_ENDPOINT).with(httpBasic(EXCHANGE_CLIENT_ID, EXCHANGE_CLIENT_SECRET))
        .param("grant_type", TOKEN_EXCHANGE_GRANT_TYPE)
        .param("subject_token", accessToken)
        .param("subject_token_type", TOKEN_TYPE_JWT)
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
    assertThat(exchangedToken.getJWTClaimsSet().getSubject(), is(CLIENT_CREDENTIALS_CLIENT_ID));
  }

  @Test
  void testSubjectMissingScopeDuringExchangeFail() throws Exception {

    mvc
      .perform(post(TOKEN_ENDPOINT).with(httpBasic(EXCHANGE_CLIENT_ID, EXCHANGE_CLIENT_SECRET))
        .param("grant_type", TOKEN_EXCHANGE_GRANT_TYPE)
        .param("subject_token", accessToken)
        .param("subject_token_type", TOKEN_TYPE_JWT)
        .param("scope", "email"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value("invalid_scope"))
      .andExpect(jsonPath("$.error_description")
        .value("scope not allowed by origin client configuration: email"));
  }

  @Test
  void testActorMissingScopeDuringExchangeFail() throws Exception {

    mvc
      .perform(post(TOKEN_ENDPOINT).with(httpBasic(EXCHANGE_CLIENT_ID, EXCHANGE_CLIENT_SECRET))
        .param("grant_type", TOKEN_EXCHANGE_GRANT_TYPE)
        .param("subject_token", accessToken)
        .param("subject_token_type", TOKEN_TYPE_JWT)
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

    // The error happens before it reaches this part
    assertFalse(found);
  }

  // Token exchange, but only subject missing the requested offline_access scope
  @Test
  void testSubjectMissingOfflineScopeDuringExchangeFail() throws Exception {

    accessToken = new AccessTokenGetter().grantType("client_credentials")
      .clientId(REGISTRATION_CLIENT_ID)
      .clientSecret(REGISTRATION_CLIENT_SECRET)
      .scope("profile")
      .getAccessTokenValue();

    mvc
      .perform(post(TOKEN_ENDPOINT).with(httpBasic(EXCHANGE_CLIENT_ID, EXCHANGE_CLIENT_SECRET))
        .param("grant_type", TOKEN_EXCHANGE_GRANT_TYPE)
        .param("subject_token", accessToken)
        .param("subject_token_type", TOKEN_TYPE_JWT)
        .param("scope", "offline_access"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value("invalid_scope"))
      .andExpect(jsonPath("$.error_description")
        .value("scope not allowed by origin client configuration: offline_access"));
  }

  // Token exchange, but only Actor missing the requested offline_access scope
  @Test
  void testActorMissingOfflineScopeDuringExchangeFail() throws Exception {

    mvc
      .perform(post(TOKEN_ENDPOINT).with(httpBasic(REGISTRATION_CLIENT_ID, REGISTRATION_CLIENT_SECRET))
        .param("grant_type", TOKEN_EXCHANGE_GRANT_TYPE)
        .param("subject_token", accessToken)
        .param("subject_token_type", TOKEN_TYPE_JWT)
        .param("scope", "offline_access"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value("invalid_scope"))
      .andExpect(jsonPath("$.error_description")
        .value("Scope 'offline_access' not allowed for client '" + REGISTRATION_CLIENT_ID + "'"));

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

    accessToken = new AccessTokenGetter().grantType(CLIENT_CREDENTIALS_GRANT_TYPE)
      .clientId(CLIENT_CREDENTIALS_CLIENT_ID)
      .clientSecret(CLIENT_CREDENTIALS_CLIENT_SECRET)
      .scope("profile")
      .getAccessTokenValue();

    mvc
      .perform(post(TOKEN_ENDPOINT).with(httpBasic(REGISTRATION_CLIENT_ID, REGISTRATION_CLIENT_SECRET))
        .param("grant_type", TOKEN_EXCHANGE_GRANT_TYPE)
        .param("subject_token", accessToken)
        .param("subject_token_type", TOKEN_TYPE_JWT)
        .param("scope", "offline_access"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value("invalid_scope"))
      .andExpect(jsonPath("$.error_description")
        .value("Scope 'offline_access' not allowed for client '" + REGISTRATION_CLIENT_ID + "'"));

    // No token introspection used whilst doing the exchange
    boolean found = logCaptor.list.stream()
      .anyMatch(event -> event.getLevel() == Level.WARN && event.getFormattedMessage()
        .contains(
            "Cannot verify requested scopes with subject token. Attempting token introspection instead."));

    // The error happens before it reaches this part
    assertFalse(found);
  }
}
