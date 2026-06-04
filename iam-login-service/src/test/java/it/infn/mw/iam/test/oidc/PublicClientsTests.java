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
package it.infn.mw.iam.test.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.JsonNode;

import it.infn.mw.iam.api.client.management.service.ClientManagementService;
import it.infn.mw.iam.api.client.registration.service.ClientRegistrationService;
import it.infn.mw.iam.api.common.client.AuthorizationGrantType;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.api.common.client.TokenEndpointAuthenticationMethod;
import it.infn.mw.iam.test.util.oidc.OidcMockMvcTestSupport;

@Transactional
public class PublicClientsTests extends OidcMockMvcTestSupport {

  @Autowired
  ClientManagementService clientManagementService;

  @Autowired
  ClientRegistrationService clientRegistrationService;

  @Test
  void clientCredentialsSuccessWithNoSecret() throws Exception {

    JsonNode json = assert200AndParse(
        postForm(TOKEN_ENDPOINT, Map.of("grant_type", "client_credentials"), PUBLIC_CLIENT_ID, ""));

    assertTrue(json.has("access_token"));
    assertEquals("Bearer", json.get("token_type").asText());
  }

  @Test
  void clientCredentialsFailsWithRandomSecret() throws Exception {

    assertEquals(401, postForm(TOKEN_ENDPOINT, Map.of("grant_type", "client_credentials"),
        PUBLIC_CLIENT_ID, "random-secret").getResponse().getStatus());
  }

  @Test
  void clientCredentialsTestsSwtichingClientAuthMethodTypeFromManagementService() throws Exception {

    RegisteredClientDTO client =
        clientManagementService.retrieveClientByClientId(PUBLIC_CLIENT_ID).orElseThrow();
    client.setTokenEndpointAuthMethod(TokenEndpointAuthenticationMethod.client_secret_basic);
    client = clientManagementService.updateClient(client.getClientId(), client);

    assertEquals(401,
        postForm(TOKEN_ENDPOINT, Map.of("grant_type", "client_credentials"), PUBLIC_CLIENT_ID, "")
          .getResponse()
          .getStatus());

    client.setTokenEndpointAuthMethod(TokenEndpointAuthenticationMethod.none);
    client = clientManagementService.updateClient(client.getClientId(), client);

    JsonNode json = assert200AndParse(
        postForm(TOKEN_ENDPOINT, Map.of("grant_type", "client_credentials"), PUBLIC_CLIENT_ID, ""));

    assertTrue(json.has("access_token"));
    assertEquals("Bearer", json.get("token_type").asText());
  }

  @Test
  @WithMockUser(username = "admin", roles = {"USER", "ADMIN"})
  void registerPublicClientAndThenSwitchAuthMethodCheckingTokenIssuing() throws Exception {

    Authentication userAuth = SecurityContextHolder.getContext().getAuthentication();
    RegisteredClientDTO clientRequest = new RegisteredClientDTO();
    clientRequest.setTokenEndpointAuthMethod(TokenEndpointAuthenticationMethod.none);
    clientRequest.setGrantTypes(Set.of(AuthorizationGrantType.CLIENT_CREDENTIALS));
    clientRequest.setClientName("public-client-test");
    RegisteredClientDTO registrationResponse =
        clientRegistrationService.registerClient(clientRequest, userAuth);
    RegisteredClientDTO updatedClient =
        clientManagementService.retrieveClientByClientId(registrationResponse.getClientId())
          .orElseThrow();
    updatedClient.setTokenEndpointAuthMethod(TokenEndpointAuthenticationMethod.client_secret_basic);
    updatedClient.setRedirectUris(Set.of("https://host-example.com/redirect-here"));
    updatedClient = clientRegistrationService.updateClient(registrationResponse.getClientId(),
        updatedClient, userAuth);

    assertEquals(401, postForm(TOKEN_ENDPOINT, Map.of("grant_type", "client_credentials"),
        registrationResponse.getClientId(), "").getResponse().getStatus());

    updatedClient.setTokenEndpointAuthMethod(TokenEndpointAuthenticationMethod.none);
    updatedClient = clientRegistrationService.updateClient(registrationResponse.getClientId(),
        updatedClient, userAuth);

    JsonNode json = assert200AndParse(postForm(TOKEN_ENDPOINT,
        Map.of("grant_type", "client_credentials"), registrationResponse.getClientId(), ""));

    assertTrue(json.has("access_token"));
    assertEquals("Bearer", json.get("token_type").asText());
  }

}
