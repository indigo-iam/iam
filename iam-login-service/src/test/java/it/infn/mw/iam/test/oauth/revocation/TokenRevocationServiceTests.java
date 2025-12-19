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

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.GrantType;

import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.core.IamTokenService;
import it.infn.mw.iam.core.oauth.revocation.TokenRevocationService;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.test.oauth.EndpointsTestUtils;
import it.infn.mw.iam.test.oauth.client_registration.ClientRegistrationTestSupport.ClientJsonStringBuilder;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@ExtendWith(SpringExtension.class)
@IamMockMvcIntegrationTest
class TokenRevocationServiceTests extends EndpointsTestUtils {

  @Autowired
  private TokenRevocationService revokeService;

  @Autowired
  private IamOAuthAccessTokenRepository accessTokenRepo;

  @Autowired
  private ClientService clientService;

  @Autowired
  private IamClientRepository clientRepo;

  @Autowired
  private ObjectMapper mapper;

  @Test
  void registrationTokenUntouchedWhenRevokingClientTokens() throws Exception {

    String clientJson = ClientJsonStringBuilder.builder()
      .scopes("openid profile offline_access")
      .grantTypes(GrantType.AUTHORIZATION_CODE.getValue())
      .build();

    RegisteredClientDTO registerResponse = mapper.readValue(mvc.perform(post(REGISTER_ENDPOINT)
        .contentType(MediaType.APPLICATION_JSON)
        .content(clientJson))
        .andExpect(status().isCreated())
        .andReturn().getResponse()
        .getContentAsString(), RegisteredClientDTO.class);

    ClientDetailsEntity client =
        clientService.findClientByClientId(registerResponse.getClientId()).orElseThrow();
    client.getGrantTypes().add(GrantType.PASSWORD.getValue());
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
    assertThat(accessToken, notNullValue());
    assertThat(refreshToken, notNullValue());

    OAuth2AccessTokenEntity registrationToken = accessTokenRepo.findByTokenValue(IamTokenService.sha256(registerResponse.getRegistrationAccessToken())).orElseThrow();
    assertThat(accessTokenRepo.findAccessTokens(client.getId()).stream().filter(at -> at.getScope().contains("registration_token")).findAny().isPresent(), is(false));
    assertThat(accessTokenRepo.findRegistrationToken(client.getId()).isPresent(), is(true));
    assertThat(accessTokenRepo.findRegistrationToken(client.getId()).get().getValue(), is(registerResponse.getRegistrationAccessToken()));
    assertThat(revokeService.isAccessTokenRevoked(registrationToken), is(false));
    revokeService.revokeAccessTokens(client);
    revokeService.revokeRefreshTokens(client);
    assertThat(accessTokenRepo.findRegistrationToken(client.getId()).isPresent(), is(true));
    assertThat(accessTokenRepo.findRegistrationToken(client.getId()).get().getValue(), is(registerResponse.getRegistrationAccessToken()));
    assertThat(accessTokenRepo.findAccessTokens(client.getId()).size(), is(0));
    assertThat(revokeService.isAccessTokenRevoked(registrationToken), is(false));
    clientService.deleteClient(client);
    assertThat(accessTokenRepo.findByTokenValue(registrationToken.getTokenValueHash()).isPresent(), is(false));

  }
}