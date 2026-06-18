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
package it.infn.mw.iam.test.api.mitre;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.mitre.openid.connect.web.ProtectedResourceRegistrationEndpoint;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.client.management.service.ClientManagementService;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.test.oauth.client_registration.ClientRegistrationTestSupport.ClientJsonStringBuilder;

@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Transactional
class ProtectedResourceIntegrationTests {

  @Autowired
  ClientManagementService managementService;

  @Autowired
  ObjectMapper mapper;

  @Autowired
  MockMvc mvc;

  private ResultActions doCreateProtectedResource(String clientJson) throws Exception {

    return mvc.perform(post("/" + ProtectedResourceRegistrationEndpoint.URL).content(clientJson)
      .contentType(APPLICATION_JSON_VALUE));
  }

  private ResultActions doGetProtectedResource(String clientId, String rat) throws Exception {

    return mvc.perform(get("/" + ProtectedResourceRegistrationEndpoint.URL + "/" + clientId)
      .header("Authorization", "Bearer " + rat)
      .accept(APPLICATION_JSON_VALUE));
  }

  private ResultActions doUpdateProtectedResource(String clientId, String clientJson, String rat)
      throws Exception {

    return mvc.perform(put("/" + ProtectedResourceRegistrationEndpoint.URL + "/" + clientId)
      .header("Authorization", "Bearer " + rat)
      .content(clientJson)
      .contentType(APPLICATION_JSON_VALUE)
      .accept(APPLICATION_JSON_VALUE));
  }

  private ResultActions doDeleteProtectedResource(String clientId, String rat) throws Exception {

    return mvc.perform(delete("/" + ProtectedResourceRegistrationEndpoint.URL + "/" + clientId)
      .header("Authorization", "Bearer " + rat)
      .accept(APPLICATION_JSON_VALUE));
  }

  @Test
  void protectedResourceLifeCycle() throws Exception {

    final String NAME = "protected-resource";
    String clientJson = ClientJsonStringBuilder.builder().name(NAME).scopes("openid").build();

    // create protected resource
    RegisteredClientDTO testedResource =
        mapper.readValue(doCreateProtectedResource(clientJson).andExpect(status().isCreated())
          .andReturn()
          .getResponse()
          .getContentAsString(), RegisteredClientDTO.class);

    // verify registration access token exists and expiration is null
    assertNull(JWTParser.parse(testedResource.getRegistrationAccessToken())
      .getJWTClaimsSet()
      .getExpirationTime());

    // retrieve protected resource directly from db
    RegisteredClientDTO fromDb =
        managementService.retrieveClientByClientId(testedResource.getClientId()).get();
    assertEquals(testedResource.getClientId(), fromDb.getClientId());
    assertTrue(fromDb.getGrantTypes().isEmpty());
    assertTrue(fromDb.getResponseTypes().isEmpty());
    assertTrue(fromDb.getRedirectUris().isEmpty());
    assertEquals(NAME, fromDb.getClientName());
    assertEquals(0, fromDb.getAccessTokenValiditySeconds());
    assertEquals(0, fromDb.getIdTokenValiditySeconds());
    assertEquals(0, fromDb.getRefreshTokenValiditySeconds());
    assertTrue(fromDb.isDynamicallyRegistered());
    assertTrue(fromDb.isAllowIntrospection());
    assertFalse(fromDb.getScope().isEmpty());
    assertEquals(1, fromDb.getScope().size());
    assertTrue(fromDb.getScope().contains("openid"));


    // retrieve protected resource from API
    RegisteredClientDTO fromAPI =
        mapper.readValue(doGetProtectedResource(testedResource.getClientId(),
            testedResource.getRegistrationAccessToken()).andExpect(status().isOk())
              .andReturn()
              .getResponse()
              .getContentAsString(),
            RegisteredClientDTO.class);

    assertEquals(testedResource.getClientId(), fromAPI.getClientId());
    assertEquals(NAME, fromAPI.getClientName());
    assertNull(fromAPI.getGrantTypes());
    assertNull(fromAPI.getResponseTypes());
    assertNull(fromAPI.getRedirectUris());
    assertNull(fromAPI.getAccessTokenValiditySeconds());
    assertNull(fromAPI.getIdTokenValiditySeconds());
    assertNull(fromAPI.getRefreshTokenValiditySeconds());
    assertEquals(0, fromAPI.getClientSecretExpiresAt().toInstant().getEpochSecond());
    assertFalse(fromAPI.getScope().isEmpty());
    assertEquals(1, fromAPI.getScope().size());
    assertTrue(fromAPI.getScope().contains("openid"));

    // update protected resource from API
    clientJson = ClientJsonStringBuilder.builder()
      .clientId(testedResource.getClientId())
      .name(NAME)
      .scopes("openid email")
      .build();
    RegisteredClientDTO updated =
        mapper.readValue(doUpdateProtectedResource(testedResource.getClientId(), clientJson,
            testedResource.getRegistrationAccessToken()).andExpect(status().isOk())
              .andReturn()
              .getResponse()
              .getContentAsString(),
            RegisteredClientDTO.class);

    assertEquals(testedResource.getClientId(), updated.getClientId());
    assertEquals(NAME, updated.getClientName());
    assertNull(updated.getGrantTypes());
    assertNull(updated.getResponseTypes());
    assertNull(updated.getRedirectUris());
    assertNull(updated.getAccessTokenValiditySeconds());
    assertNull(updated.getIdTokenValiditySeconds());
    assertNull(updated.getRefreshTokenValiditySeconds());
    assertEquals(0, updated.getClientSecretExpiresAt().toInstant().getEpochSecond());
    assertFalse(updated.getScope().isEmpty());
    assertEquals(2, updated.getScope().size());
    assertTrue(updated.getScope().contains("openid"));
    assertTrue(updated.getScope().contains("email"));

    doDeleteProtectedResource(testedResource.getClientId(),
        testedResource.getRegistrationAccessToken()).andExpect(status().isNoContent());

    assertTrue(managementService.retrieveClientByClientId(testedResource.getClientId()).isEmpty());
  }
}
