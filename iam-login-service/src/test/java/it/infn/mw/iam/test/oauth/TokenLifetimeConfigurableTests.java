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

import static it.infn.mw.iam.api.client.util.ClientSuppliers.clientNotFound;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Date;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.api.client.management.service.ClientManagementService;
import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.core.oauth.profile.IamTokenEnhancer;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@SuppressWarnings("deprecation")
@ExtendWith(SpringExtension.class)
@IamMockMvcIntegrationTest
public class TokenLifetimeConfigurableTests {

  public static final String TEST_USERNAME = "test";
  public static final String TEST_PASSWORD = "password";

  public static final String PASSWORD_GRANT_CLIENT_ID = "password-grant";
  public static final String PASSWORD_GRANT_CLIENT_SECRET = "secret";

  public static final String CLIENT_CRED_GRANT_CLIENT_ID = "client-cred";
  public static final String CLIENT_CRED_GRANT_CLIENT_SECRET = "secret";

  private static final String SCOPE = "openid profile offline_access";
  private static final String CUSTOM_LIFETIME = "300";
  private static final String INVALID_PARAMETER = IamTokenEnhancer.INVALID_PARAMETER;

  private static final long TOLERANCE = 5;
  private static final long DEFAULT_ACCESS_TOKEN_LIFETIME = 3600L;
  private static final long DEFAULT_REFRESH_TOKEN_LIFETIME = 2592000L;

  @Autowired
  private ObjectMapper mapper;

  @Autowired
  private ClientManagementService managementService;

  @Autowired
  private ClientService clientService;

  @Autowired
  private MockMvc mvc;

  @BeforeEach
  void setup() {
    ClientDetailsEntity client = clientService.findClientByClientId(PASSWORD_GRANT_CLIENT_ID)
      .orElseThrow(clientNotFound(PASSWORD_GRANT_CLIENT_SECRET));
    assertNull(client.getRefreshTokenValiditySeconds());
    client.setRefreshTokenValiditySeconds(2592000);
  }

  @Test
  void testTokenLifetimeRequestPasswordFlow() throws Exception {

    String tokenResponseJson = mvc
      .perform(post("/token").param("grant_type", "password")
        .param("client_id", PASSWORD_GRANT_CLIENT_ID)
        .param("client_secret", PASSWORD_GRANT_CLIENT_SECRET)
        .param("username", TEST_USERNAME)
        .param("password", TEST_PASSWORD)
        .param("scope", "openid profile")
        .param("expires_in", CUSTOM_LIFETIME))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    String accessToken = mapper.readTree(tokenResponseJson).get("access_token").asText();

    JWT token = JWTParser.parse(accessToken);

    JWTClaimsSet claims = token.getJWTClaimsSet();

    assertNotNull(claims.getIssueTime());
    assertNotNull(claims.getExpirationTime());
    assertThat(
        (int) (claims.getExpirationTime().getTime() - claims.getIssueTime().getTime()) / 1000,
        equalTo(Integer.parseInt(CUSTOM_LIFETIME)));
  }

  @Test
  void testTokenLifetimeRequestClientCredentialsFlow() throws Exception {

    String tokenResponseJson = mvc
      .perform(post("/token").param("grant_type", "client_credentials")
        .param("client_id", CLIENT_CRED_GRANT_CLIENT_ID)
        .param("client_secret", CLIENT_CRED_GRANT_CLIENT_SECRET)
        .param("expires_in", CUSTOM_LIFETIME))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    String accessToken = mapper.readTree(tokenResponseJson).get("access_token").asText();
    JWT token = JWTParser.parse(accessToken);

    JWTClaimsSet claims = token.getJWTClaimsSet();

    assertNotNull(claims.getIssueTime());
    assertNotNull(claims.getExpirationTime());
    assertThat(
        (int) (claims.getExpirationTime().getTime() - claims.getIssueTime().getTime()) / 1000,
        equalTo(Integer.parseInt(CUSTOM_LIFETIME)));
  }

  @Test
  void testTokenLifetimeExcceedsMax() throws Exception {
    RegisteredClientDTO clientInfDto =
        managementService.retrieveClientByClientId(CLIENT_CRED_GRANT_CLIENT_ID)
          .orElseThrow(clientNotFound(CLIENT_CRED_GRANT_CLIENT_ID));
    int maxValidity = clientInfDto.getAccessTokenValiditySeconds();

    String tokenResponseJson = mvc
      .perform(post("/token").param("grant_type", "client_credentials")
        .param("client_id", CLIENT_CRED_GRANT_CLIENT_ID)
        .param("client_secret", CLIENT_CRED_GRANT_CLIENT_SECRET)
        .param("expires_in", String.valueOf(maxValidity + 100)))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    String accessToken = mapper.readTree(tokenResponseJson).get("access_token").asText();
    JWT token = JWTParser.parse(accessToken);

    JWTClaimsSet claims = token.getJWTClaimsSet();

    assertNotNull(claims.getIssueTime());
    assertNotNull(claims.getExpirationTime());
    assertThat(
        (int) (claims.getExpirationTime().getTime() - claims.getIssueTime().getTime()) / 1000,
        equalTo(maxValidity));
  }

  @Test
  void testTokenLifetimeNegative() throws Exception {
    RegisteredClientDTO clientInfDto =
        managementService.retrieveClientByClientId(CLIENT_CRED_GRANT_CLIENT_ID)
          .orElseThrow(clientNotFound(CLIENT_CRED_GRANT_CLIENT_ID));
    int maxValidity = clientInfDto.getAccessTokenValiditySeconds();

    String tokenResponseJson = mvc
      .perform(post("/token").param("grant_type", "client_credentials")
        .param("client_id", CLIENT_CRED_GRANT_CLIENT_ID)
        .param("client_secret", CLIENT_CRED_GRANT_CLIENT_SECRET)
        .param("expires_in", String.valueOf(-5)))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    String accessToken = mapper.readTree(tokenResponseJson).get("access_token").asText();
    JWT token = JWTParser.parse(accessToken);

    JWTClaimsSet claims = token.getJWTClaimsSet();

    assertNotNull(claims.getIssueTime());
    assertNotNull(claims.getExpirationTime());
    assertThat(
        (int) (claims.getExpirationTime().getTime() - claims.getIssueTime().getTime()) / 1000,
        equalTo(maxValidity));
  }


  @Test
  void testTokenLifetimeNotInteger() throws Exception {
    mvc
      .perform(post("/token").param("grant_type", "client_credentials")
        .param("client_id", CLIENT_CRED_GRANT_CLIENT_ID)
        .param("client_secret", CLIENT_CRED_GRANT_CLIENT_SECRET)
        .param("expires_in", "test"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error_description", equalTo(INVALID_PARAMETER)));
  }

  @Test
  void testParameterRequestedDuringAccessTokenRequest() throws Exception {
    String configuredAccessTokenResponse = mvc
      .perform(
          post("/token").with(httpBasic(PASSWORD_GRANT_CLIENT_ID, PASSWORD_GRANT_CLIENT_SECRET))
            .param("grant_type", "password")
            .param("username", TEST_USERNAME)
            .param("password", TEST_PASSWORD)
            .param("scope", SCOPE)
            .param("expires_in", CUSTOM_LIFETIME))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    DefaultOAuth2AccessToken configuredAccessToken =
        mapper.readValue(configuredAccessTokenResponse, DefaultOAuth2AccessToken.class);

    String cAT = mapper.readTree(configuredAccessTokenResponse).get("access_token").asText();
    JWTClaimsSet cATClaims = JWTParser.parse(cAT).getJWTClaimsSet();

    assertNotNull(cATClaims.getIssueTime());
    assertNotNull(cATClaims.getExpirationTime());
    long diffInSeconds =
        (cATClaims.getExpirationTime().getTime() - cATClaims.getIssueTime().getTime()) / 1000;
    long customLifetime = Long.parseLong(CUSTOM_LIFETIME);
    assertThat(diffInSeconds, allOf(greaterThanOrEqualTo(customLifetime - TOLERANCE),
        lessThanOrEqualTo(customLifetime + TOLERANCE)));

    // checking that refresh token expiration is 30 days
    String refreshwithConfiguredAccessToken = configuredAccessToken.getRefreshToken().toString();
    JWTClaimsSet rtClaims = JWTParser.parse(refreshwithConfiguredAccessToken).getJWTClaimsSet();
    assertNotNull(rtClaims.getExpirationTime());
    Date currentTime = new Date();
    diffInSeconds = (rtClaims.getExpirationTime().getTime() - currentTime.getTime()) / 1000;
    assertThat(diffInSeconds,
        allOf(greaterThanOrEqualTo(DEFAULT_REFRESH_TOKEN_LIFETIME - TOLERANCE),
            lessThanOrEqualTo(DEFAULT_REFRESH_TOKEN_LIFETIME + TOLERANCE)));


    String refreshResponse = mvc
      .perform(
          post("/token").with(httpBasic(PASSWORD_GRANT_CLIENT_ID, PASSWORD_GRANT_CLIENT_SECRET))
            .param("grant_type", "refresh_token")
            .param("refresh_token", refreshwithConfiguredAccessToken))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    String refreshedAccessToken = mapper.readTree(refreshResponse).get("access_token").asText();
    JWTClaimsSet configuredClaims = JWTParser.parse(refreshedAccessToken).getJWTClaimsSet();

    assertNotNull(configuredClaims.getIssueTime());
    assertNotNull(configuredClaims.getExpirationTime());
    diffInSeconds =
        (configuredClaims.getExpirationTime().getTime() - configuredClaims.getIssueTime().getTime())
            / 1000;
    assertThat(diffInSeconds, allOf(greaterThanOrEqualTo(DEFAULT_ACCESS_TOKEN_LIFETIME - TOLERANCE),
        lessThanOrEqualTo(DEFAULT_ACCESS_TOKEN_LIFETIME + TOLERANCE)));

  }

  @Test
  void testParameterRequestedDuringRefreshTokenRequest() throws Exception {
    String ordinaryTokenResponse = mvc
      .perform(
          post("/token").with(httpBasic(PASSWORD_GRANT_CLIENT_ID, PASSWORD_GRANT_CLIENT_SECRET))
            .param("grant_type", "password")
            .param("username", TEST_USERNAME)
            .param("password", TEST_PASSWORD)
            .param("scope", SCOPE))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    DefaultOAuth2AccessToken ordinaryToken =
        mapper.readValue(ordinaryTokenResponse, DefaultOAuth2AccessToken.class);

    String oAT = mapper.readTree(ordinaryTokenResponse).get("access_token").asText();
    JWTClaimsSet oATClaims = JWTParser.parse(oAT).getJWTClaimsSet();

    assertNotNull(oATClaims.getIssueTime());
    assertNotNull(oATClaims.getExpirationTime());
    long diffInSeconds =
        (oATClaims.getExpirationTime().getTime() - oATClaims.getIssueTime().getTime()) / 1000;
    assertThat(diffInSeconds, allOf(greaterThanOrEqualTo(DEFAULT_ACCESS_TOKEN_LIFETIME - TOLERANCE),
        lessThanOrEqualTo(DEFAULT_ACCESS_TOKEN_LIFETIME + TOLERANCE)));

    // checking that refresh token expiration is 30 days
    String ordinaryRefresh = ordinaryToken.getRefreshToken().toString();
    JWTClaimsSet rtClaims = JWTParser.parse(ordinaryRefresh).getJWTClaimsSet();
    assertNotNull(rtClaims.getExpirationTime());
    Date currentTime = new Date();
    diffInSeconds = (rtClaims.getExpirationTime().getTime() - currentTime.getTime()) / 1000;
    assertThat(diffInSeconds,
        allOf(greaterThanOrEqualTo(DEFAULT_REFRESH_TOKEN_LIFETIME - TOLERANCE),
            lessThanOrEqualTo(DEFAULT_REFRESH_TOKEN_LIFETIME + TOLERANCE)));

    String requestedParameterResponse = mvc
      .perform(
          post("/token").with(httpBasic(PASSWORD_GRANT_CLIENT_ID, PASSWORD_GRANT_CLIENT_SECRET))
            .param("grant_type", "refresh_token")
            .param("refresh_token", ordinaryRefresh)
            .param("expires_in", CUSTOM_LIFETIME))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    String ordinaryAccessToken =
        mapper.readTree(requestedParameterResponse).get("access_token").asText();
    JWTClaimsSet ordinaryClaims = JWTParser.parse(ordinaryAccessToken).getJWTClaimsSet();

    assertNotNull(ordinaryClaims.getIssueTime());
    assertNotNull(ordinaryClaims.getExpirationTime());
    diffInSeconds =
        (ordinaryClaims.getExpirationTime().getTime() - ordinaryClaims.getIssueTime().getTime())
            / 1000;
    long customLifetime = Long.parseLong(CUSTOM_LIFETIME);
    assertThat(diffInSeconds, allOf(greaterThanOrEqualTo(customLifetime - TOLERANCE),
        lessThanOrEqualTo(customLifetime + TOLERANCE)));
  }

}
