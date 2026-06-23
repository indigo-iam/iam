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

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.api.client.util.ClientSuppliers;
import it.infn.mw.iam.persistence.model.IamAup;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAupRepository;
import it.infn.mw.iam.test.config.ClockConfig;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.util.TokenGetterUtils;
import it.infn.mw.iam.test.util.clock.MutableClock;
import it.infn.mw.iam.test.util.oauth.SecurityContextUtils;

@SuppressWarnings("deprecation")
@SpringBootTest(classes = {IamLoginService.class, CoreControllerTestSupport.class, ClockConfig.class},
    webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Transactional
class RefreshTokenGranterTests extends TokenGetterUtils {

  static final String SCOPES_STR = "openid profile offline_access";

  @Autowired
  ObjectMapper mapper;

  @Autowired
  IamAupRepository aupRepo;

  @Autowired
  IamAccountRepository accountRepo;

  @Autowired
  ClientService clientService;

  @Autowired
  SecurityContextUtils sc;

  @Autowired
  MutableClock clock;

  @Test
  void testTokenRefreshFailsIfAupIsNotSigned() throws Exception {

    String clientId = "password-grant";
    String clientSecret = "secret";

    // @formatter:off
    String response = mvc.perform(post("/token")
        .with(httpBasic(clientId, clientSecret))
        .param("grant_type", "password")
        .param("username", TEST_USERNAME)
        .param("password", TEST_PASSWORD)
        .param("scope", SCOPES_STR))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();
    // @formatter:on

    DefaultOAuth2AccessToken tokenResponse =
        mapper.readValue(response, DefaultOAuth2AccessToken.class);

    String refreshToken = tokenResponse.getRefreshToken().toString();

    IamAup aup = new IamAup();

    aup.setCreationTime(clock.now());
    aup.setLastUpdateTime(clock.now());
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
  void testRefreshFlowNotAllowedIfUserIsSuspended() throws Exception {

    String clientId = "password-grant";
    String clientSecret = "secret";

    // @formatter:off
    String response = mvc.perform(post("/token")
        .with(httpBasic(clientId, clientSecret))
        .param("grant_type", "password")
        .param("username", TEST_USERNAME)
        .param("password", TEST_PASSWORD)
        .param("scope", SCOPES_STR))
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
  void testRefreshFlowNotAllowedIfClientIsSuspended() throws Exception {

    String clientId = "password-grant";
    String clientSecret = "secret";

    // @formatter:off
    String response = mvc.perform(post("/token")
        .with(httpBasic(clientId, clientSecret))
        .param("grant_type", "password")
        .param("username", TEST_USERNAME)
        .param("password", TEST_PASSWORD)
        .param("scope", SCOPES_STR))
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
      .andExpect(jsonPath("$.error_description").value("Suspended client '" + clientId + "'"));
    // @formatter:on

    client.setActive(true);
    clientService.updateClient(client);
  }
}
