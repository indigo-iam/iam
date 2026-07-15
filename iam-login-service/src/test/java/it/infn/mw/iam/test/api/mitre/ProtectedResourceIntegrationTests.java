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

import static it.infn.mw.iam.api.client.registration.ProtectedResourceRegistrationApiController.PROTECTED_RESOURCE_ENDPOINT;
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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.JsonObject;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.client.management.service.ClientManagementService;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;

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

    return mvc.perform(
        post(PROTECTED_RESOURCE_ENDPOINT).content(clientJson).contentType(APPLICATION_JSON_VALUE));
  }

  private ResultActions doGetProtectedResource(String clientId, String rat) throws Exception {

    return mvc.perform(
        get(PROTECTED_RESOURCE_ENDPOINT + "/" + clientId).header("Authorization", "Bearer " + rat)
          .accept(APPLICATION_JSON_VALUE));
  }

  private ResultActions doUpdateProtectedResource(String clientId, String clientJson, String rat)
      throws Exception {

    return mvc.perform(
        put(PROTECTED_RESOURCE_ENDPOINT + "/" + clientId).header("Authorization", "Bearer " + rat)
          .content(clientJson)
          .contentType(APPLICATION_JSON_VALUE)
          .accept(APPLICATION_JSON_VALUE));
  }

  private ResultActions doDeleteProtectedResource(String clientId, String rat) throws Exception {

    return mvc.perform(delete(PROTECTED_RESOURCE_ENDPOINT + "/" + clientId)
      .header("Authorization", "Bearer " + rat)
      .accept(APPLICATION_JSON_VALUE));
  }

  @Test
  void protectedResourceLifeCycle() throws Exception {

    final String NAME = "protected-resource";
    final String SCOPES = "profile email";

    JsonObject clientJson = new JsonObject();
    clientJson.addProperty("client_name", NAME);
    clientJson.addProperty("scope", SCOPES);

    // create protected resource
    RegisteredClientDTO testedResource = mapper
      .readValue(doCreateProtectedResource(clientJson.toString()).andExpect(status().isCreated())
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
    assertEquals(0L, fromDb.getClientSecretExpiresAt());
    assertTrue(fromDb.isDynamicallyRegistered());
    assertFalse(fromDb.getScope().isEmpty());
    assertEquals(2, fromDb.getScope().size());
    assertTrue(fromDb.getScope().contains("profile"));
    assertTrue(fromDb.getScope().contains("email"));

    doGetProtectedResource(testedResource.getClientId(), "invalid-token")
      .andExpect(status().isUnauthorized());

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
    assertEquals(0L, fromAPI.getClientSecretExpiresAt());
    assertFalse(fromAPI.getScope().isEmpty());
    assertEquals(2, fromAPI.getScope().size());
    assertTrue(fromAPI.getScope().contains("profile"));
    assertTrue(fromAPI.getScope().contains("email"));

    clientJson = new JsonObject();
    clientJson.addProperty("client_name", NAME);
    clientJson.addProperty("scope", "openid email");

    doUpdateProtectedResource(testedResource.getClientId(), clientJson.toString(), "invalid-token")
      .andExpect(status().isUnauthorized());

    RegisteredClientDTO updated = mapper
      .readValue(doUpdateProtectedResource(testedResource.getClientId(), clientJson.toString(),
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
    assertEquals(0L, updated.getClientSecretExpiresAt());
    assertFalse(updated.getScope().isEmpty());
    assertEquals(2, updated.getScope().size());
    assertTrue(updated.getScope().contains("openid"));
    assertTrue(updated.getScope().contains("email"));

    doDeleteProtectedResource(testedResource.getClientId(), "invalid-token")
      .andExpect(status().isUnauthorized());

    doDeleteProtectedResource(testedResource.getClientId(),
        testedResource.getRegistrationAccessToken()).andExpect(status().isNoContent());

    assertTrue(managementService.retrieveClientByClientId(testedResource.getClientId()).isEmpty());
  }
}
