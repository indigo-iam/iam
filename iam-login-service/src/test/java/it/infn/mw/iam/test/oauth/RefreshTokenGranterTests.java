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

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.text.ParseException;
import java.util.Date;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.oauth2.model.AuthenticationHolderEntity;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWT;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.api.client.util.ClientSuppliers;
import it.infn.mw.iam.audit.events.tokens.AccessTokenIssuedEvent;
import it.infn.mw.iam.persistence.model.IamAup;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAupRepository;
import it.infn.mw.iam.test.api.tokens.TestTokensUtils;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@SuppressWarnings("deprecation")
@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
public class RefreshTokenGranterTests extends TestTokensUtils {

  private static final String USERNAME = "test";
  private static final String PASSWORD = "password";
  private static final String SCOPE = "openid profile offline_access";
  public static final String[] SCOPES = {"openid", "profile", "offline_access"};

  @Autowired
  private ObjectMapper mapper;

  @Autowired
  private IamAupRepository aupRepo;

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private ClientService clientService;

  @Autowired
  private MockMvc mvc;

  @Test
  public void testTokenRefreshFailsIfAupIsNotSigned() throws Exception {

    String clientId = "password-grant";
    String clientSecret = "secret";

    // @formatter:off
    String response = mvc.perform(post("/token")
        .with(httpBasic(clientId, clientSecret))
        .param("grant_type", "password")
        .param("username", USERNAME)
        .param("password", PASSWORD)
        .param("scope", SCOPE))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();
    // @formatter:on

    DefaultOAuth2AccessToken tokenResponse =
        mapper.readValue(response, DefaultOAuth2AccessToken.class);

    String refreshToken = tokenResponse.getRefreshToken().toString();

    IamAup aup = new IamAup();

    aup.setCreationTime(new Date());
    aup.setLastUpdateTime(new Date());
    aup.setName("default-aup");
    aup.setUrl("http://default-aup.org/");
    aup.setDescription("AUP description");
    aup.setSignatureValidityInDays(0L);
    aup.setAupRemindersInDays("30,15,1");

    aupRepo.save(aup);

    // @formatter:off
    mvc.perform(post("/token")
        .with(httpBasic(clientId, clientSecret))
        .param("grant_type", "refresh_token")
        .param("refresh_token", refreshToken))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value("invalid_grant"))
      .andExpect(jsonPath("$.error_description").value("User test needs to sign AUP for this organization in order to proceed."));
    // @formatter:on

    aupRepo.delete(aup);

    // @formatter:off
    mvc.perform(post("/token")
        .with(httpBasic(clientId, clientSecret))
        .param("grant_type", "refresh_token")
        .param("refresh_token", refreshToken))
      .andExpect(status().isOk());
    // @formatter:on

  }

  @Test
  public void testRefreshFlowNotAllowedIfUserIsSuspended() throws Exception {

    String clientId = "password-grant";
    String clientSecret = "secret";

    // @formatter:off
    String response = mvc.perform(post("/token")
        .with(httpBasic(clientId, clientSecret))
        .param("grant_type", "password")
        .param("username", USERNAME)
        .param("password", PASSWORD)
        .param("scope", SCOPE))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();
    // @formatter:on

    DefaultOAuth2AccessToken tokenResponse =
        mapper.readValue(response, DefaultOAuth2AccessToken.class);

    String refreshToken = tokenResponse.getRefreshToken().toString();

    accountRepo.findByUsername("test").get().setActive(false);

    // @formatter:off
    mvc.perform(post("/token")
        .with(httpBasic(clientId, clientSecret))
        .param("grant_type", "refresh_token")
        .param("refresh_token", refreshToken))
      .andExpect(status().isUnauthorized())
      .andExpect(jsonPath("$.error").value("unauthorized"))
      .andExpect(jsonPath("$.error_description").value("User test is not active."));
    // @formatter:on

    accountRepo.findByUsername("test").get().setActive(true);
  }

  @Test
  public void testRefreshFlowNotAllowedIfClientIsSuspended() throws Exception {

    String clientId = "password-grant";
    String clientSecret = "secret";

    // @formatter:off
    String response = mvc.perform(post("/token")
        .with(httpBasic(clientId, clientSecret))
        .param("grant_type", "password")
        .param("username", USERNAME)
        .param("password", PASSWORD)
        .param("scope", SCOPE))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();
    // @formatter:on

    DefaultOAuth2AccessToken tokenResponse =
        mapper.readValue(response, DefaultOAuth2AccessToken.class);

    String refreshToken = tokenResponse.getRefreshToken().toString();

    ClientDetailsEntity client = clientService.findClientByClientId(clientId)
      .orElseThrow(ClientSuppliers.clientNotFound(clientId));

    client.setActive(false);
    clientService.updateClient(client);

    // @formatter:off
    mvc.perform(post("/token")
        .with(httpBasic(clientId, clientSecret))
        .param("grant_type", "refresh_token")
        .param("refresh_token", refreshToken))
      .andExpect(status().isUnauthorized())
      .andExpect(jsonPath("$.error").value("invalid_client"))
      .andExpect(jsonPath("$.error_description").value("Client is suspended: " + clientId));
    // @formatter:on

    client.setActive(true);
    clientService.updateClient(client);
  }

  @Test
  public void testRefreshTokenParsingThrowsParseException() throws Exception {

    OAuth2AccessTokenEntity accessToken = Mockito.mock(OAuth2AccessTokenEntity.class);
    OAuth2RefreshTokenEntity refreshToken = Mockito.mock(OAuth2RefreshTokenEntity.class);
    AuthenticationHolderEntity authnHolder = Mockito.mock(AuthenticationHolderEntity.class);
    OAuth2Authentication authn = Mockito.mock(OAuth2Authentication.class);
    OAuth2Request req = Mockito.mock(OAuth2Request.class);

    JWT jwt = Mockito.mock(JWT.class);

    when(accessToken.getRefreshToken()).thenReturn(refreshToken);
    when(accessToken.getAuthenticationHolder()).thenReturn(authnHolder);
    when(accessToken.getAuthenticationHolder().getAuthentication()).thenReturn(authn);
    when(authn.getOAuth2Request()).thenReturn(req);
    when(accessToken.getJwt()).thenReturn(jwt);
    JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
    when(jwt.getHeader()).thenReturn(header);
    when(accessToken.getRefreshToken().getJwt()).thenReturn(jwt);
    when(jwt.getJWTClaimsSet()).thenThrow(new ParseException("parse error", 0));

    AccessTokenIssuedEvent event = new AccessTokenIssuedEvent(this, accessToken);

    assertNull(event.getRefreshTokenJti());

  }

  @Test
  public void testRefreshTokenJtiInAccessTokenAuditLogs() throws Exception {

    String clientId = "password-grant";
    ClientDetailsEntity client = loadTestClient(clientId);

    OAuth2AccessTokenEntity accessToken = buildAccessToken(client, USERNAME, SCOPES);

    String refreshTokenJti = accessToken.getRefreshToken().getJwt().getJWTClaimsSet().getJWTID();

    AccessTokenIssuedEvent event = new AccessTokenIssuedEvent(this, accessToken);
    assertTrue(event.getRefreshTokenJti().equals(refreshTokenJti));

  }

}
