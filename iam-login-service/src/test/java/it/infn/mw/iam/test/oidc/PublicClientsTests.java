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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.text.ParseException;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.JsonNode;

import it.infn.mw.iam.api.client.error.InvalidClientRegistrationRequest;
import it.infn.mw.iam.api.client.management.service.ClientManagementService;
import it.infn.mw.iam.api.client.registration.service.ClientRegistrationService;
import it.infn.mw.iam.api.common.client.AuthorizationGrantType;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.api.common.client.TokenEndpointAuthenticationMethod;
import it.infn.mw.iam.test.util.oidc.OidcMockMvcTestSupport;

@SuppressWarnings("deprecation")
@Transactional
class PublicClientsTests extends OidcMockMvcTestSupport {

    private final String NEW_PUBLIC_CLIENT_ID = "new-public-client";

  @Autowired
  ClientManagementService clientManagementService;

  @Autowired
  ClientRegistrationService clientRegistrationService;

  @Test
  void publicClientCannotUseClientCredentialsGrant() throws Exception {

    MvcResult result = postForm(TOKEN_ENDPOINT,
        Map.of("grant_type", "client_credentials", "client_id", PUBLIC_CLIENT_ID), null, null);

    assertEquals(401, result.getResponse().getStatus());

    JsonNode json = mapper.readTree(result.getResponse().getContentAsString());
    assertTrue(!json.has("access_token"));
  }

  @Test
  void publicClientCannotUseClientCredentialsWithEmptyFormSecret() throws Exception {

    MvcResult result = postForm(TOKEN_ENDPOINT, Map.of("grant_type", "client_credentials",
        "client_id", PUBLIC_CLIENT_ID, "client_secret", ""), null, null);

    assertEquals(401, result.getResponse().getStatus());

    JsonNode json = mapper.readTree(result.getResponse().getContentAsString());
    assertTrue(json.has("error"));
    assertTrue(!json.has("access_token"));
  }

  @Test
  void publicClientCannotUseClientCredentialsWithBasicAuthentication() throws Exception {

    MvcResult result =
        postForm(TOKEN_ENDPOINT, Map.of("grant_type", "client_credentials"), PUBLIC_CLIENT_ID, "");

    assertEquals(401, result.getResponse().getStatus());

    JsonNode json = mapper.readTree(result.getResponse().getContentAsString());
    assertTrue(json.has("error"));
    assertTrue(!json.has("access_token"));
  }

  @Test
  void clientCredentialsFailsWithRandomSecret() throws Exception {

    assertEquals(401, postForm(TOKEN_ENDPOINT, Map.of("grant_type", "client_credentials"),
        PUBLIC_CLIENT_ID, "random-secret").getResponse().getStatus());
    assertEquals(401,
        postForm(TOKEN_ENDPOINT, Map.of("grant_type", "client_credentials", "client_id",
            PUBLIC_CLIENT_ID, "client_secret", "random-secret"), null, null).getResponse()
              .getStatus());
  }

  @Test
  void clientCredentialsFailsWhenPublicSecretHasASecret() throws Exception {

    assertEquals(401,
        postForm(TOKEN_ENDPOINT,
            Map.of("grant_type", "client_credentials", "client_id", PUBLIC_CLIENT_WITH_SECRET_ID),
            null, null).getResponse().getStatus());
    assertEquals(401,
        postForm(TOKEN_ENDPOINT, Map.of("grant_type", "client_credentials", "client_id",
            PUBLIC_CLIENT_WITH_SECRET_ID, "client_secret", "secret"), null, null).getResponse()
              .getStatus());
    assertEquals(401, postForm(TOKEN_ENDPOINT, Map.of("grant_type", "client_credentials"),
        PUBLIC_CLIENT_WITH_SECRET_ID, "secret").getResponse().getStatus());
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
    RegisteredClientDTO publicClient = client;
    assertThrows(InvalidRequestException.class,
        () -> clientManagementService.updateClient(publicClient.getClientId(), publicClient));
  }

  private void grantAdminScopesToPublicClient() throws ParseException {

      // Making a new public client to not change the clients state across the tests
      // in this class
      RegisteredClientDTO clientDTO = new RegisteredClientDTO();
      clientDTO.setClientName(NEW_PUBLIC_CLIENT_ID);
      clientDTO.setClientId(NEW_PUBLIC_CLIENT_ID);

      clientManagementService.saveNewClient(clientDTO);

      RegisteredClientDTO clientNew = clientManagementService.retrieveClientByClientId(NEW_PUBLIC_CLIENT_ID)
              .orElseThrow();

      // Making it public
      clientNew.setTokenEndpointAuthMethod(TokenEndpointAuthenticationMethod.none);
      // Set public client as admin user
      clientNew.setScope(Set.of("openid", "profile", "email", "iam:admin.write", "scim:read"));
      clientNew.setGrantTypes(Set.of(AuthorizationGrantType.PASSWORD));

      clientManagementService.updateClient(clientNew.getClientId(), clientNew);

  }

  @Test
  void publicClientRequestingAdminScopeWithPasswordGrantIsRejectedEvenForAdminUser()
      throws Exception {
    grantAdminScopesToPublicClient();

    MvcResult result = postForm(TOKEN_ENDPOINT, Map.of("grant_type", "password", "username",
        "admin", "password", "password", "scope", "openid iam:admin.write"), NEW_PUBLIC_CLIENT_ID, "");

    assertPublicClientAdminScopeError(result);
  }

  private void assertPublicClientAdminScopeError(MvcResult result) throws Exception {
    assertEquals(400, result.getResponse().getStatus());
    JsonNode json = mapper.readTree(result.getResponse().getContentAsString());
    assertEquals("invalid_request", json.get("error").asText());
    assertEquals("Public clients are not allowed to request iam:admin or scim scopes",
        json.get("error_description").asText());
  }

  @Test
  @WithMockUser(username = "admin", roles = {"USER", "ADMIN"})
  void registerPublicClientAndThenSwitchAuthMethodCheckingTokenIssuing() throws Exception {

    Authentication userAuth = SecurityContextHolder.getContext().getAuthentication();
    RegisteredClientDTO clientRequest = new RegisteredClientDTO();
    clientRequest.setTokenEndpointAuthMethod(TokenEndpointAuthenticationMethod.none);
    clientRequest.setGrantTypes(Set.of(AuthorizationGrantType.CLIENT_CREDENTIALS));
    clientRequest.setClientName("public-client-test");
    assertThrows(InvalidClientRegistrationRequest.class,
        () -> clientRegistrationService.registerClient(clientRequest, userAuth));
    clientRequest.setTokenEndpointAuthMethod(TokenEndpointAuthenticationMethod.client_secret_basic);
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
    RegisteredClientDTO publicClient = updatedClient;
    assertThrows(InvalidClientRegistrationRequest.class, () -> clientRegistrationService
      .updateClient(registrationResponse.getClientId(), publicClient, userAuth));
  }

}
