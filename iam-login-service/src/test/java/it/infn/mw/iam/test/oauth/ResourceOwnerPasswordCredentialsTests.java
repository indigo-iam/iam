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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.Assert.assertNotNull;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Date;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.oauth2.service.OAuth2TokenEntityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAup;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAupRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;


@SuppressWarnings("deprecation")
@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
public class ResourceOwnerPasswordCredentialsTests {

  private static final String GRANT_TYPE = "password";
  private static final String USERNAME = "test";
  private static final String PASSWORD = "password";
  private static final String SCOPE = "openid profile";

  @Autowired
  private ObjectMapper mapper;

  @Autowired
  private IamAupRepository aupRepo;

  @Autowired
  private IamAccountService accountService;

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private OAuth2TokenEntityService tokenService;

  @Autowired
  private IamOAuthAccessTokenRepository accessTokenRepo;

  @Autowired
  private IamOAuthRefreshTokenRepository refreshTokenRepo;

  @Autowired
  private MockMvc mvc;

  @Before
  public void setup() throws Exception {
    accessTokenRepo.deleteAll();
    refreshTokenRepo.deleteAll();
  }

  @Test
  public void testResourceOwnerPasswordCredentialsFlow() throws Exception {

    String clientId = "password-grant";
    String clientSecret = "secret";

    // @formatter:off
    mvc.perform(post("/token")
        .with(httpBasic(clientId, clientSecret))
        .param("grant_type", GRANT_TYPE)
        .param("username", USERNAME)
        .param("password", PASSWORD)
        .param("scope", SCOPE))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.scope", equalTo(SCOPE)));
    // @formatter:on
  }

  @Test
  public void testResourceOwnerPasswordCredentialsFailsIfAupIsNotSigned() throws Exception {

    IamAup aup = new IamAup();

    aup.setCreationTime(new Date());
    aup.setLastUpdateTime(new Date());
    aup.setName("default-aup");
    aup.setUrl("http://default-aup.org/");
    aup.setDescription("AUP description");
    aup.setSignatureValidityInDays(0L);

    aupRepo.save(aup);


    String clientId = "password-grant";
    String clientSecret = "secret";

    // @formatter:off
    mvc.perform(post("/token")
        .with(httpBasic(clientId, clientSecret))
        .param("grant_type", GRANT_TYPE)
        .param("username", USERNAME)
        .param("password", PASSWORD)
        .param("scope", SCOPE))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value("invalid_grant"))
      .andExpect(jsonPath("$.error_description").value("User test needs to sign AUP for this organization in order to proceed."));
    // @formatter:on
  }

  @Test
  public void testInvalidResourceOwnerPasswordCredentials() throws Exception {

    String clientId = "password-grant";
    String clientSecret = "secret";

    // @formatter:off
    mvc.perform(post("/token")
        .with(httpBasic(clientId, clientSecret))
        .param("grant_type", GRANT_TYPE)
        .param("username", USERNAME)
        .param("password", "wrong_password")
        .param("scope", SCOPE))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", equalTo("invalid_grant")))
      .andExpect(jsonPath("$.error_description", equalTo("Bad credentials")));
    // @formatter:on
  }

  @Test
  public void testResourceOwnerPasswordCredentialsInvalidClientCredentials() throws Exception {

    String clientId = "password-grant";
    String clientSecret = "socret";

    // @formatter:off
    mvc.perform(post("/token")
        .with(httpBasic(clientId, clientSecret))
        .param("grant_type", GRANT_TYPE)
        .param("username", USERNAME)
        .param("password", PASSWORD)
        .param("scope", SCOPE))
      .andExpect(status().isUnauthorized())
      .andExpect(jsonPath("$.error", equalTo("unauthorized")))
      .andExpect(jsonPath("$.error_description", equalTo("Bad credentials")))
      ;
    // @formatter:on
  }

  @Test
  public void testResourceOwnerPasswordCredentialsUnknownClient() throws Exception {

    String clientId = "unknown";
    String clientSecret = "socret";

    // @formatter:off
    mvc.perform(post("/token")
        .with(httpBasic(clientId, clientSecret))
        .param("grant_type", GRANT_TYPE)
        .param("username", USERNAME)
        .param("password", PASSWORD)
        .param("scope", SCOPE)
        .contentType(MediaType.APPLICATION_FORM_URLENCODED))
      .andExpect(status().isUnauthorized())
      .andExpect(jsonPath("$.error", equalTo("unauthorized")))
      .andExpect(jsonPath("$.error_description", equalTo("Bad credentials")))
      ;
    // @formatter:on
  }

  @Test
  public void testResourceOwnerPasswordCredentialAuthenticationTimestamp() throws Exception {

    String clientId = "password-grant";
    String clientSecret = "secret";

    // @formatter:off
    String response = mvc.perform(post("/token")
        .with(httpBasic(clientId, clientSecret))
        .param("grant_type", GRANT_TYPE)
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

    String idToken = tokenResponse.getAdditionalInformation().get("id_token").toString();

    JWT token = JWTParser.parse(idToken);
    assertNotNull(token.getJWTClaimsSet().getClaim("auth_time"));
  }

  @Test
  public void testTokensAreCleanedUpWhenAccountRemoved() throws Exception {

    String clientId = "password-grant";
    String clientSecret = "secret";

    // @formatter:off
    mvc.perform(post("/token")
        .with(httpBasic(clientId, clientSecret))
        .param("grant_type", GRANT_TYPE)
        .param("username", USERNAME)
        .param("password", PASSWORD)
        .param("scope", "openid profile offline_access"))
      .andExpect(status().isOk());
    // @formatter:on

    assertThat(tokenService.getAllAccessTokensForUser(USERNAME), hasSize(1));
    assertThat(tokenService.getAllRefreshTokensForUser(USERNAME), hasSize(1));

    IamAccount testAccount = accountRepo.findByUsername(USERNAME)
      .orElseThrow(() -> new AssertionError(String.format("Expected %s user not found", USERNAME)));

    accountService.deleteAccount(testAccount);

    assertThat(tokenService.getAllAccessTokensForUser(USERNAME), hasSize(0));
    assertThat(tokenService.getAllRefreshTokensForUser(USERNAME), hasSize(0));

  }
}
