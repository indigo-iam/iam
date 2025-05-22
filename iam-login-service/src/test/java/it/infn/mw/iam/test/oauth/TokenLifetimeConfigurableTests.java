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
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.api.client.management.service.ClientManagementService;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
public class TokenLifetimeConfigurableTests {

  public static final String TEST_USERNAME = "test";
  public static final String TEST_PASSWORD = "password";

  public static final String PASSWORD_GRANT_CLIENT_ID = "password-grant";
  public static final String PASSWORD_GRANT_CLIENT_SECRET = "secret";

  public static final String CLIENT_CRED_GRANT_CLIENT_ID = "client-cred";
  public static final String CLIENT_CRED_GRANT_CLIENT_SECRET = "secret";

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
        .param("expires_in", "300"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    String accessToken = mapper.readTree(tokenResponseJson).get("access_token").asText();

    JWT token = JWTParser.parse(accessToken);

    JWTClaimsSet claims = token.getJWTClaimsSet();

    assertNotNull(claims.getIssueTime());
    assertNotNull(claims.getExpirationTime());
    assertThat((int) (claims.getExpirationTime().getTime() - claims.getIssueTime().getTime()) / 1000, equalTo(300));
  }

  @Test
  public void testTokenLifetimeRequestClientCredentialsFlow() throws Exception {

    String tokenResponseJson = mvc
      .perform(post("/token").param("grant_type", "client_credentials")
        .param("client_id", CLIENT_CRED_GRANT_CLIENT_ID)
        .param("client_secret", CLIENT_CRED_GRANT_CLIENT_SECRET)
        .param("expires_in", "300"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    String accessToken = mapper.readTree(tokenResponseJson).get("access_token").asText();
    JWT token = JWTParser.parse(accessToken);

    JWTClaimsSet claims = token.getJWTClaimsSet();

    assertNotNull(claims.getIssueTime());
    assertNotNull(claims.getExpirationTime());
    assertThat((int) (claims.getExpirationTime().getTime() - claims.getIssueTime().getTime()) / 1000, equalTo(300));
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
    assertThat((int) (claims.getExpirationTime().getTime() - claims.getIssueTime().getTime()) / 1000, equalTo(maxValidity));
  }

}