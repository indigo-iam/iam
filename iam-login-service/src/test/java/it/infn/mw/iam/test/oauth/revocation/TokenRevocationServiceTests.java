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
package it.infn.mw.iam.test.oauth.revocation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.core.TokenUtils;
import it.infn.mw.iam.core.oauth.revocation.TokenRevocationService;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.model.OAuth2AccessTokenEntity;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.test.oauth.EndpointsTestUtils;
import it.infn.mw.iam.test.oauth.client_registration.ClientRegistrationTestSupport.ClientJsonStringBuilder;

@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK,
    properties = {"iam.access_token.store_on_database=true"})
@AutoConfigureMockMvc
@Transactional
class TokenRevocationServiceTests extends EndpointsTestUtils {

  @Autowired
  TokenRevocationService revokeService;

  @Autowired
  IamOAuthAccessTokenRepository accessTokenRepo;

  @Autowired
  ClientService clientService;

  @Autowired
  IamClientRepository clientRepo;

  @Autowired
  ObjectMapper mapper;

  @Autowired
  TokenUtils tokenUtils;

  @Test
  void registrationTokenUntouchedWhenRevokingClientTokens() throws Exception {

    String clientJson = ClientJsonStringBuilder.builder()
      .scopes("openid profile offline_access")
      .grantTypes(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
      .build();

    RegisteredClientDTO registerResponse = mapper.readValue(mvc
      .perform(post(REGISTER_ENDPOINT).contentType(MediaType.APPLICATION_JSON).content(clientJson))
      .andExpect(status().isCreated())
      .andReturn()
      .getResponse()
      .getContentAsString(), RegisteredClientDTO.class);

    ClientDetailsEntity client =
        clientService.findClientByClientId(registerResponse.getClientId()).orElseThrow();
    client.getGrantTypes().add(AuthorizationGrantType.PASSWORD.getValue());
    clientRepo.save(client);

    TokenEndpointResponse tokenResponse = parseTokens(new AccessTokenGetter().grantType("password")
      .clientId(client.getClientId())
      .clientSecret(client.getClientSecret())
      .username(TEST_USERNAME)
      .password(TEST_PASSWORD)
      .scope("openid profile offline_access")
      .getTokenResponseObject());

    String accessToken = tokenResponse.accessToken();
    String refreshToken = tokenResponse.refreshToken();
    assertNotNull(accessToken);
    assertNotNull(refreshToken);

    OAuth2AccessTokenEntity registrationToken = accessTokenRepo
      .findByTokenValue(tokenUtils.sha256(registerResponse.getRegistrationAccessToken()))
      .orElseThrow();
    assertFalse(accessTokenRepo.findAccessTokens(client.getId())
      .stream()
      .filter(at -> at.getScope().contains("registration_token"))
      .findAny()
      .isPresent());
    assertTrue(accessTokenRepo.findRegistrationToken(client.getId()).isPresent());
    assertEquals(registerResponse.getRegistrationAccessToken(),
        accessTokenRepo.findRegistrationToken(client.getId()).get().getValue());
    assertFalse(revokeService.isAccessTokenRevoked(registrationToken));
    revokeService.revokeAccessTokens(client);
    assertTrue(revokeService.isAccessTokenRevoked(accessToken));
    revokeService.revokeRefreshTokens(client);
    assertTrue(accessTokenRepo.findRegistrationToken(client.getId()).isPresent());
    assertEquals(registerResponse.getRegistrationAccessToken(),
        accessTokenRepo.findRegistrationToken(client.getId()).get().getValue());
    assertEquals(0, accessTokenRepo.findAccessTokens(client.getId()).size());
    assertFalse(revokeService.isAccessTokenRevoked(registrationToken));
    clientService.deleteClient(client);
    assertFalse(
        accessTokenRepo.findByTokenValue(registrationToken.getTokenValueHash()).isPresent());
  }
}
