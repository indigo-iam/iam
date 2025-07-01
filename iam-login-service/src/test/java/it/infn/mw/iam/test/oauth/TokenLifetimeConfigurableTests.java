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
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertNotNull;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.api.client.management.service.ClientManagementService;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.core.oauth.profile.common.BaseAccessTokenBuilder;

@SuppressWarnings("deprecation")
@RunWith(SpringRunner.class)
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
    private static final String INVALID_PARAMETER = BaseAccessTokenBuilder.INVALID_PARAMETER;

    @Autowired
    private ObjectMapper mapper;

    @Autowired
    private ClientManagementService managementService;

    @Autowired
    private MockMvc mvc;

    @Test
    public void testTokenLifetimeRequestPasswordFlow() throws Exception {

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
        assertThat((int) (claims.getExpirationTime().getTime() - claims.getIssueTime().getTime()) / 1000,
                equalTo(Integer.parseInt(CUSTOM_LIFETIME)));
    }

    @Test
    public void testTokenLifetimeRequestClientCredentialsFlow() throws Exception {

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
        assertThat((int) (claims.getExpirationTime().getTime() - claims.getIssueTime().getTime()) / 1000,
                equalTo(Integer.parseInt(CUSTOM_LIFETIME)));
    }

    @Test
    public void testTokenLifetimeExcceedsMax() throws Exception {
        RegisteredClientDTO clientInfDto = managementService.retrieveClientByClientId(CLIENT_CRED_GRANT_CLIENT_ID)
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
        assertThat((int) (claims.getExpirationTime().getTime() - claims.getIssueTime().getTime()) / 1000,
                equalTo(maxValidity));
    }

    @Test
    public void testTokenLifetimeNegative() throws Exception {
        mvc.perform(post("/token").param("grant_type", "client_credentials")
                .param("client_id", CLIENT_CRED_GRANT_CLIENT_ID)
                .param("client_secret", CLIENT_CRED_GRANT_CLIENT_SECRET)
                .param("expires_in", String.valueOf(-5)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error_description", equalTo(INVALID_PARAMETER)));
    }

    @Test
    public void testTokenLifetimeNotInteger() throws Exception {
        mvc.perform(post("/token").param("grant_type", "client_credentials")
                .param("client_id", CLIENT_CRED_GRANT_CLIENT_ID)
                .param("client_secret", CLIENT_CRED_GRANT_CLIENT_SECRET)
                .param("expires_in", "test"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error_description", equalTo(INVALID_PARAMETER)));
    }

    @Test
    public void testTokenLifetimeRequestRefreshFlow() throws Exception {

        String clientId = "password-grant";
        String clientSecret = "secret";

        String ordinaryTokenResponse = mvc.perform(post("/token")
                .with(httpBasic(clientId, clientSecret))
                .param("grant_type", "password")
                .param("username", TEST_USERNAME)
                .param("password", TEST_PASSWORD)
                .param("scope", SCOPE))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

    // @formatter:off
    String configuredLifetimeTokenResponse = mvc.perform(post("/token")
        .with(httpBasic(clientId, clientSecret))
        .param("grant_type", "password")
        .param("username", TEST_USERNAME)
        .param("password", TEST_PASSWORD)
        .param("scope", SCOPE)
        .param("expires_in", CUSTOM_LIFETIME))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();
    // @formatter:on

        DefaultOAuth2AccessToken ordinaryToken = mapper.readValue(ordinaryTokenResponse,
                DefaultOAuth2AccessToken.class);

        String ordinaryRefresh = ordinaryToken.getRefreshToken().toString();

        DefaultOAuth2AccessToken tokenResponse = mapper.readValue(configuredLifetimeTokenResponse,
                DefaultOAuth2AccessToken.class);

        String refreshwithConfiguredAccessToken = tokenResponse.getRefreshToken().toString();

    // @formatter:off
    String ordinaryReponse = mvc.perform(post("/token")
        .with(httpBasic(clientId, clientSecret))
        .param("grant_type", "refresh_token")
        .param("refresh_token", ordinaryRefresh))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();
    // @formatter:on

    // @formatter:off
    String configuredReponse = mvc.perform(post("/token")
        .with(httpBasic(clientId, clientSecret))
        .param("grant_type", "refresh_token")
        .param("refresh_token", refreshwithConfiguredAccessToken))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();
    // @formatter:on

        String ordinaryAccessToken = mapper.readTree(ordinaryReponse).get("access_token").asText();
        JWTClaimsSet ordinaryClaims = JWTParser.parse(ordinaryAccessToken).getJWTClaimsSet();

        assertNotNull(ordinaryClaims.getIssueTime());
        assertNotNull(ordinaryClaims.getExpirationTime());
        assertThat(
                (int) (ordinaryClaims.getExpirationTime().getTime() - ordinaryClaims.getIssueTime().getTime()) / 1000,
                equalTo(3600));

        String configuredAccessToken = mapper.readTree(configuredReponse).get("access_token").asText();
        JWTClaimsSet configuredClaims = JWTParser.parse(configuredAccessToken).getJWTClaimsSet();

        assertNotNull(configuredClaims.getIssueTime());
        assertNotNull(configuredClaims.getExpirationTime());
        assertThat(
                (int) (configuredClaims.getExpirationTime().getTime() - configuredClaims.getIssueTime().getTime())
                        / 1000,
                equalTo(Integer.parseInt(CUSTOM_LIFETIME)));
    }

}