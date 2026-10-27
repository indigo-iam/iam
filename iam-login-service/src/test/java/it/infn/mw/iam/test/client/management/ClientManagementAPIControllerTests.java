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
package it.infn.mw.iam.test.client.management;

import static it.infn.mw.iam.api.common.client.AuthorizationGrantType.CLIENT_CREDENTIALS;
import static it.infn.mw.iam.api.common.client.TokenEndpointAuthenticationMethod.client_secret_basic;
import static it.infn.mw.iam.api.common.client.TokenEndpointAuthenticationMethod.none;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultMatcher;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.api.common.client.AuthorizationGrantType;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.api.common.client.TokenEndpointAuthenticationMethod;
import it.infn.mw.iam.persistence.model.ClientAuthMethod;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@IamMockMvcIntegrationTest
class ClientManagementAPIControllerTests {

  static final String IAM_CLIENTS_API_URL = "/iam/api/clients/";
  static final String JSON_PATCH_CONTENT_TYPE = "application/json-patch+json";

  static final ResultMatcher UNAUTHORIZED = status().isUnauthorized();
  static final ResultMatcher BAD_REQUEST = status().isBadRequest();
  static final ResultMatcher CREATED = status().isCreated();
  static final ResultMatcher OK = status().isOk();
  static final ResultMatcher FORBIDDEN = status().isForbidden();

  @Autowired
  MockMvc mvc;

  @Autowired
  ObjectMapper mapper;

  @Autowired
  IamClientRepository clientRepository;

  @Autowired
  MockOAuth2Filter oauth2Filter;

  @BeforeEach
  void setup() {
    oauth2Filter.cleanupSecurityContext();
  }

  @AfterEach
  void teardown() {
    oauth2Filter.cleanupSecurityContext();
  }

  @Test
  @WithAnonymousUser
  void createClientWithAnonymousUser() throws Exception {

    RegisteredClientDTO client = new RegisteredClientDTO();
    client.setClientName("test-client-creation");
    client.setClientId("test-client-creation");
    client.setGrantTypes(Set.of(AuthorizationGrantType.CLIENT_CREDENTIALS));
    client.setScope(Set.of("test"));

    mvc
      .perform(post(IAM_CLIENTS_API_URL).with(csrf().asHeader())
        .contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(client)))
      .andExpect(UNAUTHORIZED);
  }

  @Test
  @WithMockUser(username = "test", roles = "USER")
  void createClientWithUser() throws Exception {

    RegisteredClientDTO client = new RegisteredClientDTO();
    client.setClientName("test-client-creation");
    client.setClientId("test-client-creation");
    client.setGrantTypes(Set.of(AuthorizationGrantType.CLIENT_CREDENTIALS));
    client.setScope(Set.of("test"));

    Optional<ClientDetailsEntity> newClient =
        clientRepository.findByClientId("test-client-creation");

    assertThrows(NoSuchElementException.class, newClient::get);

    mvc
      .perform(post(IAM_CLIENTS_API_URL).contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(client)))
      .andExpect(FORBIDDEN);
  }

  @Test
  @WithMockUser(username = "test", roles = "USER")
  void updateClientWithUser() throws Exception {

    RegisteredClientDTO client = new RegisteredClientDTO();
    client.setClientName("test-client-creation");
    client.setClientId("client");
    client.setGrantTypes(Set.of(AuthorizationGrantType.CLIENT_CREDENTIALS));
    client.setScope(Set.of("test"));

    ClientDetailsEntity clientEntity = clientRepository.findByClientId("client").get();

    assertEquals("client", clientEntity.getClientId());

    mvc.perform(put(IAM_CLIENTS_API_URL + clientEntity.getClientId()).contentType(APPLICATION_JSON)
      .content(mapper.writeValueAsString(client))).andExpect(FORBIDDEN);
  }

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  void updateAuthMethodToNone() throws Exception {

    RegisteredClientDTO client = new RegisteredClientDTO();
    client.setClientName("test-client-creation");
    client.setClientId("test-client-creation");
    client.setGrantTypes(Set.of(CLIENT_CREDENTIALS));
    client.setScope(Set.of("test"));

    mvc
      .perform(post(IAM_CLIENTS_API_URL).with(csrf().asHeader())
        .contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(client)))
      .andExpect(CREATED)
      .andExpect(jsonPath("$.token_endpoint_auth_method", is(client_secret_basic.name())));

    client.setTokenEndpointAuthMethod(none);

    mvc
      .perform(put(IAM_CLIENTS_API_URL + "/test-client-creation").with(csrf().asHeader())
        .contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(client)))
      .andExpect(OK)
      .andExpect(jsonPath("$.token_endpoint_auth_method", is("none")));

    ClientDetailsEntity clientEntity =
        clientRepository.findByClientId("test-client-creation").get();
    assertEquals(ClientAuthMethod.NONE, clientEntity.getTokenEndpointAuthMethod());
  }

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  void createClientUpscopingOff() throws Exception {

    RegisteredClientDTO client = new RegisteredClientDTO();
    client.setClientName("test-client-creation");
    client.setClientId("test-client-creation");
    client.setGrantTypes(Set.of(CLIENT_CREDENTIALS));
    client.setScope(Set.of("test"));
    client.setUpScopingEnabled(false);

    mvc
      .perform(post(IAM_CLIENTS_API_URL).with(csrf().asHeader())
        .contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(client)))
      .andExpect(CREATED)
      .andExpect(jsonPath("$.token_endpoint_auth_method", is(client_secret_basic.name())));

    ClientDetailsEntity clientEntity =
        clientRepository.findByClientId("test-client-creation").get();
    assertEquals(false, clientEntity.isUpScopingEnabled());
  }

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  void createClientUpscopingOn() throws Exception {

    RegisteredClientDTO client = new RegisteredClientDTO();
    client.setClientName("test-client-creation");
    client.setClientId("test-client-creation");
    client.setGrantTypes(Set.of(CLIENT_CREDENTIALS));
    client.setScope(Set.of("test"));

    mvc
      .perform(post(IAM_CLIENTS_API_URL).with(csrf().asHeader())
        .contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(client)))
      .andExpect(CREATED)
      .andExpect(jsonPath("$.token_endpoint_auth_method", is(client_secret_basic.name())));

    ClientDetailsEntity clientEntity =
        clientRepository.findByClientId("test-client-creation").get();
    assertEquals(true, clientEntity.isUpScopingEnabled());
  }

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  void updateClientUpscopingOff() throws Exception {

    RegisteredClientDTO client = new RegisteredClientDTO();
    client.setClientName("test-client-creation");
    client.setClientId("test-client-creation");
    client.setGrantTypes(Set.of(CLIENT_CREDENTIALS));
    client.setScope(Set.of("test"));

    mvc
      .perform(post(IAM_CLIENTS_API_URL).with(csrf().asHeader())
        .contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(client)))
      .andExpect(CREATED)
      .andExpect(jsonPath("$.token_endpoint_auth_method", is(client_secret_basic.name())));

    ClientDetailsEntity clientEntity =
        clientRepository.findByClientId("test-client-creation").get();
    assertEquals(true, clientEntity.isUpScopingEnabled());

    client.setUpScopingEnabled(false);

    mvc
      .perform(put(IAM_CLIENTS_API_URL + "/test-client-creation").with(csrf().asHeader())
        .contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(client)))
      .andExpect(OK);

    clientEntity = clientRepository.findByClientId("test-client-creation").get();
    assertEquals(false, clientEntity.isUpScopingEnabled());
  }

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  void updateClientUpscopingOn() throws Exception {

    RegisteredClientDTO client = new RegisteredClientDTO();
    client.setClientName("test-client-creation");
    client.setClientId("test-client-creation");
    client.setGrantTypes(Set.of(CLIENT_CREDENTIALS));
    client.setScope(Set.of("test"));
    client.setUpScopingEnabled(false);

    mvc
      .perform(post(IAM_CLIENTS_API_URL).with(csrf().asHeader())
        .contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(client)))
      .andExpect(CREATED)
      .andExpect(jsonPath("$.token_endpoint_auth_method", is(client_secret_basic.name())));

    ClientDetailsEntity clientEntity =
        clientRepository.findByClientId("test-client-creation").get();
    assertEquals(false, clientEntity.isUpScopingEnabled());

    client.setUpScopingEnabled(true);

    mvc
      .perform(put(IAM_CLIENTS_API_URL + "/test-client-creation").with(csrf().asHeader())
        .contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(client)))
      .andExpect(OK);

    clientEntity = clientRepository.findByClientId("test-client-creation").get();
    assertEquals(true, clientEntity.isUpScopingEnabled());
  }

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  void createClientRaiseParseException() throws Exception {

    final String NOT_A_JSON_STRING = "This is not a JSON string";

    RegisteredClientDTO client = new RegisteredClientDTO();
    client.setClientName("test-client-creation");
    client.setClientId("test-client-creation");
    client.setGrantTypes(Set.of(AuthorizationGrantType.CLIENT_CREDENTIALS));
    client.setScope(Set.of("test"));
    client.setTokenEndpointAuthMethod(TokenEndpointAuthenticationMethod.private_key_jwt);
    client.setJwk(NOT_A_JSON_STRING);

    mvc
      .perform(post(IAM_CLIENTS_API_URL).with(csrf().asHeader())
        .contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(client)))
      .andExpect(BAD_REQUEST)
      .andExpect(jsonPath("$.error", startsWith("Invalid JSON object")));

  }

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  void createClientRaiseURIValidationException() throws Exception {

    final String NOT_A_URI_STRING = "This is not a URI string";

    RegisteredClientDTO client = new RegisteredClientDTO();
    client.setClientName("test-client-creation");
    client.setClientId("test-client-creation");
    client.setGrantTypes(Set.of(AuthorizationGrantType.CLIENT_CREDENTIALS));
    client.setScope(Set.of("test"));
    client.setTokenEndpointAuthMethod(TokenEndpointAuthenticationMethod.private_key_jwt);
    client.setJwksUri(NOT_A_URI_STRING);

    String expectedMessage = "saveNewClient.client.jwksUri: must be a valid URL";

    mvc
      .perform(post(IAM_CLIENTS_API_URL).with(csrf().asHeader())
        .contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(client)))
      .andExpect(BAD_REQUEST)
      .andExpect(jsonPath("$.error", is(expectedMessage)));

  }

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  void createClientPrivateJwtValidationException() throws Exception {

    final String URI_STRING = "http://localhost:8080/jwk";
    final String NOT_A_JSON_STRING = "This is not a JSON string";

    RegisteredClientDTO client = new RegisteredClientDTO();
    client.setClientName("test-client-creation");
    client.setClientId("test-client-creation");
    client.setGrantTypes(Set.of(AuthorizationGrantType.CLIENT_CREDENTIALS));
    client.setScope(Set.of("test"));
    client.setTokenEndpointAuthMethod(TokenEndpointAuthenticationMethod.private_key_jwt);

    String expectedMessage =
        "saveNewClient.client: private_key_jwt requires a jwks uri or a jwk value";

    mvc
      .perform(post(IAM_CLIENTS_API_URL).with(csrf().asHeader())
        .contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(client)))
      .andExpect(BAD_REQUEST)
      .andExpect(jsonPath("$.error", is(expectedMessage)));

    client.setJwk(NOT_A_JSON_STRING);
    client.setJwksUri(URI_STRING);

    try {
      mvc
        .perform(post(IAM_CLIENTS_API_URL).with(csrf().asHeader())
          .contentType(APPLICATION_JSON)
          .content(mapper.writeValueAsString(client)))
        .andExpect(CREATED);
    } finally {
      mvc.perform(delete(IAM_CLIENTS_API_URL + client.getClientId()));
    }
  }

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  void updateClientPrivateJwtValidationException() throws Exception {

    RegisteredClientDTO client = new RegisteredClientDTO();
    client.setClientName("test-client-creation");
    client.setClientId("test-client-creation");
    client.setGrantTypes(Set.of(AuthorizationGrantType.CLIENT_CREDENTIALS));
    client.setScope(Set.of("test"));

    mvc
      .perform(post(IAM_CLIENTS_API_URL).with(csrf().asHeader())
        .contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(client)))
      .andExpect(CREATED);

    client.setTokenEndpointAuthMethod(TokenEndpointAuthenticationMethod.private_key_jwt);

    String expectedMessage =
        "updateClient.client: private_key_jwt requires a jwks uri or a jwk value";

    mvc
      .perform(put(IAM_CLIENTS_API_URL + client.getClientId()).contentType(APPLICATION_JSON)
        .with(csrf().asHeader())
        .content(mapper.writeValueAsString(client)))
      .andExpect(BAD_REQUEST)
      .andExpect(jsonPath("$.error", is(expectedMessage)));

  }

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  void testReturnClientSecret() throws Exception {
    String clientPassword = "password";

    RegisteredClientDTO client = new RegisteredClientDTO();
    client.setClientName("test-client-creation");
    client.setClientId("test-client-creation");
    client.setGrantTypes(Set.of(AuthorizationGrantType.CLIENT_CREDENTIALS));
    client.setScope(Set.of("test"));
    client.setClientSecret(clientPassword);

    String responseJson = mvc
      .perform(post(IAM_CLIENTS_API_URL).with(csrf().asHeader())
        .contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(client)))
      .andExpect(CREATED)
      .andReturn()
      .getResponse()
      .getContentAsString();

    client = mapper.readValue(responseJson, RegisteredClientDTO.class);
    assertNotNull(client.getClientSecret());
    assertThat(client.getClientSecret().equals(clientPassword), is(true));

    responseJson = mvc
      .perform(put(IAM_CLIENTS_API_URL + client.getClientId()).contentType(APPLICATION_JSON)
        .with(csrf().asHeader())
        .content(mapper.writeValueAsString(client)))
      .andExpect(OK)
      .andReturn()
      .getResponse()
      .getContentAsString();

    RegisteredClientDTO clientDto = mapper.readValue(responseJson, RegisteredClientDTO.class);
    assertNull(clientDto.getClientSecret());
  }

  private static Map<String, Object> replaceOp(String path, String value) {
    return Map.of("op", "replace", "path", path, "value", value);
  }

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  void patchClientNameAndDescription() throws Exception {

    RegisteredClientDTO client = new RegisteredClientDTO();
    client.setClientName("test-client-patch");
    client.setClientId("test-client-patch");
    client.setGrantTypes(Set.of(CLIENT_CREDENTIALS));
    client.setScope(Set.of("test"));

    mvc
      .perform(post(IAM_CLIENTS_API_URL).contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(client)))
      .andExpect(CREATED);

    String patchBody = mapper.writeValueAsString(List.of(
        replaceOp("/client_name", "patched-client-name"),
        replaceOp("/client_description", "patched client description")));

    mvc
      .perform(patch(IAM_CLIENTS_API_URL + "test-client-patch").contentType(JSON_PATCH_CONTENT_TYPE)
        .content(patchBody))
      .andExpect(OK)
      .andExpect(jsonPath("$.client_name", is("patched-client-name")))
      .andExpect(jsonPath("$.client_description", is("patched client description")));

    ClientDetailsEntity clientEntity = clientRepository.findByClientId("test-client-patch").get();
    assertEquals("patched-client-name", clientEntity.getClientName());
    assertEquals("patched client description", clientEntity.getClientDescription());
  }

  @Test
  @WithMockUser(username = "test", roles = "USER")
  void patchClientWithUserIsForbidden() throws Exception {

    String patchBody = mapper.writeValueAsString(List.of(replaceOp("/client_name", "new-name")));

    mvc
      .perform(patch(IAM_CLIENTS_API_URL + "client").contentType(JSON_PATCH_CONTENT_TYPE)
        .content(patchBody))
      .andExpect(FORBIDDEN);
  }

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  void patchClientRejectsUnsupportedPath() throws Exception {

    String patchBody =
        mapper.writeValueAsString(List.of(replaceOp("/client_id", "another-client-id")));

    mvc
      .perform(patch(IAM_CLIENTS_API_URL + "client").contentType(JSON_PATCH_CONTENT_TYPE)
        .content(patchBody))
      .andExpect(BAD_REQUEST)
      .andExpect(jsonPath("$.error", startsWith("Unsupported patch path")));
  }

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  void patchClientRejectsUnsupportedOperation() throws Exception {

    String patchBody =
        mapper.writeValueAsString(List.of(Map.of("op", "remove", "path", "/client_name")));

    mvc
      .perform(patch(IAM_CLIENTS_API_URL + "client").contentType(JSON_PATCH_CONTENT_TYPE)
        .content(patchBody))
      .andExpect(BAD_REQUEST)
      .andExpect(jsonPath("$.error", startsWith("Unsupported patch operation")));
  }

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  void patchClientRejectsNonStringValue() throws Exception {

    String patchBody =
        mapper.writeValueAsString(List.of(Map.of("op", "replace", "path", "/client_name", "value", 42)));

    mvc
      .perform(patch(IAM_CLIENTS_API_URL + "client").contentType(JSON_PATCH_CONTENT_TYPE)
        .content(patchBody))
      .andExpect(BAD_REQUEST)
      .andExpect(jsonPath("$.error", is("Patch operation for path '/client_name' requires a string value")));
  }

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  void patchClientRejectsInvalidSize() throws Exception {

    String tooLongName = "n".repeat(300);
    String patchBody = mapper.writeValueAsString(List.of(replaceOp("/client_name", tooLongName)));

    mvc
      .perform(patch(IAM_CLIENTS_API_URL + "client").contentType(JSON_PATCH_CONTENT_TYPE)
        .content(patchBody))
      .andExpect(BAD_REQUEST);
  }

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  void patchClientRejectsPlainJsonContentType() throws Exception {

    String patchBody = mapper.writeValueAsString(List.of(replaceOp("/client_name", "new-name")));

    mvc
      .perform(patch(IAM_CLIENTS_API_URL + "client").contentType(APPLICATION_JSON)
        .content(patchBody))
      .andExpect(status().isUnsupportedMediaType());
  }

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  void patchClientRejectsMissingValue() throws Exception {

    String patchBody =
        mapper.writeValueAsString(List.of(Map.of("op", "replace", "path", "/client_name")));

    mvc
      .perform(patch(IAM_CLIENTS_API_URL + "client").contentType(JSON_PATCH_CONTENT_TYPE)
        .content(patchBody))
      .andExpect(BAD_REQUEST)
      .andExpect(jsonPath("$.error",
          is("Patch operation 'replace' for path '/client_name' requires a 'value' member")));
  }

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  void patchClientNotFound() throws Exception {

    String patchBody = mapper.writeValueAsString(List.of(replaceOp("/client_name", "new-name")));

    mvc
      .perform(
          patch(IAM_CLIENTS_API_URL + "does-not-exist").contentType(JSON_PATCH_CONTENT_TYPE)
            .content(patchBody))
      .andExpect(status().isNotFound());
  }
}
