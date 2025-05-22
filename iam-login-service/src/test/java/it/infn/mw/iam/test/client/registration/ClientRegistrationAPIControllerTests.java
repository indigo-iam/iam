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
package it.infn.mw.iam.test.client.registration;

import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultMatcher;
import org.testcontainers.shaded.com.google.common.collect.Sets;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.api.common.client.AuthorizationGrantType;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.api.common.client.TokenEndpointAuthenticationMethod;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
class ClientRegistrationAPIControllerTests {

  @Autowired
  private MockMvc mvc;

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  @Autowired
  private ObjectMapper mapper;

  @Autowired
  private IamClientRepository clientRepository;

  @Autowired
  private ClientService clientService;

  public static final String IAM_CLIENT_REGISTRATION_API_URL = "/iam/api/client-registration/";

  public static final ResultMatcher UNAUTHORIZED = status().isUnauthorized();
  public static final ResultMatcher BAD_REQUEST = status().isBadRequest();
  public static final ResultMatcher CREATED = status().isCreated();

  @BeforeEach
  public void setup() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @AfterEach
  public void cleanup() {
    mockOAuth2Filter.cleanupSecurityContext();
    clientService.findClientByClientId("test-client-creation")
      .ifPresent(c -> clientService.deleteClient(c));;
  }

  @Test
  @WithAnonymousUser
  public void registerClientWithNullValuesAndCheckDefaultValues()
      throws JsonProcessingException, Exception {

    RegisteredClientDTO client = new RegisteredClientDTO();
    client.setClientName("test-client-creation");
    client.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.DEVICE_CODE));
    client.setScope(Sets.newHashSet("test"));
    client.setAccessTokenValiditySeconds(null);
    client.setRefreshTokenValiditySeconds(null);
    client.setTokenEndpointAuthMethod(null);

    RegisteredClientDTO response = mapper.readValue(mvc
      .perform(post(IAM_CLIENT_REGISTRATION_API_URL).contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(client)))
      .andExpect(CREATED)
      .andExpect(jsonPath("$.client_id").exists())
      .andExpect(jsonPath("$.client_secret").exists())
      .andExpect(jsonPath("$.client_name", is("test-client-creation")))
      .andExpect(jsonPath("$.scope", is("test")))
      .andExpect(jsonPath("$.grant_types").isArray())
      .andExpect(jsonPath("$.grant_types", hasItem("urn:ietf:params:oauth:grant-type:device_code")))
      .andExpect(jsonPath("$.token_endpoint_auth_method", is("client_secret_basic")))
      .andExpect(jsonPath("$.dynamically_registered", is(true)))
      .andExpect(jsonPath("$.active", is(true)))
      .andExpect(jsonPath("$.registration_access_token").exists())
      .andExpect(jsonPath("$.allow_introspection").doesNotExist())
      .andExpect(jsonPath("$.access_token_validity_seconds").doesNotExist())
      .andExpect(jsonPath("$.refresh_token_validity_seconds").doesNotExist())
      .andExpect(jsonPath("$.id_token_validity_seconds").doesNotExist())
      .andExpect(jsonPath("$.device_code_validity_seconds").doesNotExist())
      .andReturn()
      .getResponse()
      .getContentAsString(), RegisteredClientDTO.class);

    ClientDetailsEntity createdClient =
        clientRepository.findByClientId(response.getClientId()).get();

    assertEquals(3600, createdClient.getAccessTokenValiditySeconds());
    assertEquals(2592000, createdClient.getRefreshTokenValiditySeconds());

    client = new RegisteredClientDTO();
    client.setClientName("test-client-creation");
    client.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CLIENT_CREDENTIALS));
    client.setScope(Sets.newHashSet("test"));
    client.setAccessTokenValiditySeconds(null);
    client.setRefreshTokenValiditySeconds(null);
    client.setTokenEndpointAuthMethod(null);

    mvc
      .perform(post(IAM_CLIENT_REGISTRATION_API_URL).contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(client)))
      .andExpect(BAD_REQUEST);
  }

  @Test
  @WithAnonymousUser
  public void registerClientRaiseParseException() throws JsonProcessingException, Exception {

    final String NOT_A_JSON_STRING = "This is not a JSON string";

    RegisteredClientDTO client = new RegisteredClientDTO();
    client.setClientName("test-client-creation");
    client.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CLIENT_CREDENTIALS));
    client.setScope(Sets.newHashSet("test"));
    client.setTokenEndpointAuthMethod(TokenEndpointAuthenticationMethod.private_key_jwt);
    client.setJwk(NOT_A_JSON_STRING);

    mvc
      .perform(post(IAM_CLIENT_REGISTRATION_API_URL).contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(client)))
      .andExpect(BAD_REQUEST)
      .andExpect(jsonPath("$.error", startsWith("Invalid JSON:")));

  }

  @Test
  @WithAnonymousUser
  public void registerClientRaiseJwkUriValidationException()
      throws JsonProcessingException, Exception {

    final String NOT_A_URI_STRING = "This is not a URI";

    RegisteredClientDTO client = new RegisteredClientDTO();
    client.setClientName("test-client-creation");
    client.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CLIENT_CREDENTIALS));
    client.setScope(Sets.newHashSet("test"));
    client.setTokenEndpointAuthMethod(TokenEndpointAuthenticationMethod.private_key_jwt);
    client.setJwksUri(NOT_A_URI_STRING);

    String expectedMessage = "registerClient.request.jwksUri: must be a valid URL";

    mvc
      .perform(post(IAM_CLIENT_REGISTRATION_API_URL).contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(client)))
      .andExpect(BAD_REQUEST)
      .andExpect(jsonPath("$.error", is(expectedMessage)));

  }

  @Test
  @WithAnonymousUser
  public void registerClientPrivateJwtValidationException()
      throws JsonProcessingException, Exception {

    final String URI_STRING = "http://localhost:8080/jwk";
    final String NOT_A_JSON_STRING = "This is not a JSON string";

    RegisteredClientDTO client = new RegisteredClientDTO();
    client.setClientName("test-client-creation");
    client.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.DEVICE_CODE));
    client.setScope(Sets.newHashSet("test"));
    client.setTokenEndpointAuthMethod(TokenEndpointAuthenticationMethod.private_key_jwt);

    String expectedMessage =
        "registerClient.request: private_key_jwt requires a jwks uri or a jwk value";

    mvc
      .perform(post(IAM_CLIENT_REGISTRATION_API_URL).contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(client)))
      .andExpect(BAD_REQUEST)
      .andExpect(jsonPath("$.error", is(expectedMessage)));

    client.setJwk(NOT_A_JSON_STRING);
    client.setJwksUri(URI_STRING);

    try {
      mvc
        .perform(post(IAM_CLIENT_REGISTRATION_API_URL).contentType(APPLICATION_JSON)
          .content(mapper.writeValueAsString(client)))
        .andExpect(CREATED);
    } finally {
      mvc.perform(delete(IAM_CLIENT_REGISTRATION_API_URL + client.getClientId()));
    }

    client = new RegisteredClientDTO();
    client.setClientName("test-client-creation");
    client.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.CLIENT_CREDENTIALS));
    client.setScope(Sets.newHashSet("test"));
    client.setTokenEndpointAuthMethod(TokenEndpointAuthenticationMethod.private_key_jwt);

    expectedMessage = "registerClient.request: private_key_jwt requires a jwks uri or a jwk value";

    mvc
      .perform(post(IAM_CLIENT_REGISTRATION_API_URL).contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(client)))
      .andExpect(BAD_REQUEST)
      .andExpect(jsonPath("$.error", is(expectedMessage)));

    client.setJwk(NOT_A_JSON_STRING);
    client.setJwksUri(URI_STRING);

    expectedMessage = "Grant type not allowed: client_credentials";

    mvc
      .perform(post(IAM_CLIENT_REGISTRATION_API_URL).contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(client)))
      .andExpect(BAD_REQUEST)
      .andExpect(jsonPath("$.error", is(expectedMessage)));

  }

  @Test
  @WithAnonymousUser
  public void updateClientPrivateJwtValidationException()
      throws JsonProcessingException, Exception {

    RegisteredClientDTO client = new RegisteredClientDTO();
    client.setClientName("test-client-creation");
    client.setGrantTypes(Sets.newHashSet(AuthorizationGrantType.DEVICE_CODE));
    client.setScope(Sets.newHashSet("test"));

    mvc
      .perform(post(IAM_CLIENT_REGISTRATION_API_URL).contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(client)))
      .andExpect(CREATED);

    client.setTokenEndpointAuthMethod(TokenEndpointAuthenticationMethod.private_key_jwt);

    String expectedMessage =
        "updateClient.request: private_key_jwt requires a jwks uri or a jwk value";

    mvc
      .perform(
          put(IAM_CLIENT_REGISTRATION_API_URL + client.getClientId()).contentType(APPLICATION_JSON)
            .content(mapper.writeValueAsString(client)))
      .andExpect(BAD_REQUEST)
      .andExpect(jsonPath("$.error", is(expectedMessage)));

  }


}
