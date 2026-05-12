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

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.test.oauth.scope.StructuredScopeTestSupportConstants;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
class TokenEndpointClientAuthenticationTests implements StructuredScopeTestSupportConstants {

  private static final String SCOPE = "read-tasks";
  private static final String SCOPE_SUBSET = "openid";

  @Autowired
  private MockMvc mvc;

  @Autowired
  private ObjectMapper mapper;

  @Test
  void testTokenEndpointFormClientAuthentication() throws Exception {

    // @formatter:off
    mvc.perform(post(TOKEN_ENDPOINT)
        .param("grant_type", CLIENT_CREDENTIALS_GRANT_TYPE)
        .param("client_id", CLIENT_CREDENTIALS_CLIENT_ID)
        .param("client_secret", CLIENT_CREDENTIALS_CLIENT_SECRET)
        .param("scope", SCOPE))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.scope", equalTo(SCOPE)));
    // @formatter:on
  }

  @Test
  void testTokenEndpointFormClientAuthenticationInvalidCredentials() throws Exception {

    final String wrongSecret = "wrong-secret";

    // @formatter:off
    mvc.perform(post(TOKEN_ENDPOINT)
        .param("grant_type", CLIENT_CREDENTIALS_GRANT_TYPE)
        .param("client_id", CLIENT_CREDENTIALS_CLIENT_ID)
        .param("client_secret", wrongSecret)
        .param("scope", SCOPE))
      .andExpect(status().isUnauthorized())
      .andExpect(jsonPath("$.error", equalTo("invalid_client")))
      .andExpect(jsonPath("$.error_description", equalTo("Bad client credentials")));
    // @formatter:on
  }

  @Test
  void testTokenEndpointFormClientAuthenticationUnknownClient() throws Exception {

    final String unknownClientId = "unknown-client";

    // @formatter:off
    mvc.perform(post(TOKEN_ENDPOINT)
        .param("grant_type", CLIENT_CREDENTIALS_GRANT_TYPE)
        .param("client_id", unknownClientId)
        .param("client_secret", CLIENT_CREDENTIALS_CLIENT_SECRET)
        .param("scope", SCOPE))
      .andExpect(status().isUnauthorized())
      .andExpect(jsonPath("$.error", equalTo("invalid_client")))
      .andExpect(jsonPath("$.error_description", equalTo("Bad client credentials")));
    // @formatter:on
  }

  @Test
  void testTokenEndpointBasicClientAuthentication() throws Exception {

    // @formatter:off
    mvc.perform(post(TOKEN_ENDPOINT)
        .with(httpBasic(CLIENT_CREDENTIALS_CLIENT_ID, CLIENT_CREDENTIALS_CLIENT_SECRET))
        .param("grant_type", CLIENT_CREDENTIALS_GRANT_TYPE)
        .param("scope", SCOPE))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.scope", equalTo(SCOPE)));
    // @formatter:on
  }

  @Test
  void testTokenEndpointPublicClientAuthentication() throws Exception {

    // @formatter:off
    mvc.perform(post(TOKEN_ENDPOINT)
        .param("grant_type", CLIENT_CREDENTIALS_GRANT_TYPE)
        .param("client_id", PUBLIC_CLIENT_ID))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.scope", containsString("profile")))
      .andExpect(jsonPath("$.scope", containsString("email")));
    // @formatter:on
  }

  @Test
  void testTokenEndpointOptionsMethodAllowed() throws Exception {
    mvc.perform(options(TOKEN_ENDPOINT)).andExpect(status().isOk());
  }

  @Test
  @WithAnonymousUser
  void testInsufficientScopedClientCredentialTokenForbidsAccess() throws Exception {

    String response = mvc
      .perform(post(TOKEN_ENDPOINT).with(httpBasic(SCIM_CLIENT_RW_ID, SCIM_CLIENT_RW_SECRET))
        .param("grant_type", CLIENT_CREDENTIALS_GRANT_TYPE)
        .param("scope", SCOPE_SUBSET))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.scope", equalTo(SCOPE_SUBSET)))
      .andExpect(jsonPath("$.scope", not(containsString("scim:read"))))
      .andExpect(jsonPath("$.scope", not(containsString("scim:write"))))
      .andReturn()
      .getResponse()
      .getContentAsString();

    ObjectMapper mapper = new ObjectMapper();
    String accessTokenNoSCIM = mapper.readTree(response).get("access_token").asText();

    String scimAuthorizationHeader = String.format("Bearer %s", accessTokenNoSCIM);

    mvc.perform(get("/scim/Users").header("Authorization", scimAuthorizationHeader))
      .andExpect(status().isForbidden());

    mvc.perform(get("/scim/Users/" + TEST_UUID).header("Authorization", scimAuthorizationHeader))
      .andExpect(status().isForbidden());

    mvc.perform(delete("/scim/Users/" + TEST_UUID).header("Authorization", scimAuthorizationHeader))
      .andExpect(status().isForbidden());

    mvc.perform(get("/scim/Groups").header("Authorization", scimAuthorizationHeader))
      .andExpect(status().isForbidden());

    mvc
      .perform(get("/scim/Groups/" + PRODUCTION_GROUP_UUID).header("Authorization",
          scimAuthorizationHeader))
      .andExpect(status().isForbidden());

    mvc
      .perform(delete("/scim/Groups/" + PRODUCTION_GROUP_UUID).header("Authorization",
          scimAuthorizationHeader))
      .andExpect(status().isForbidden());
  }

  @Test
  @WithAnonymousUser
  void testSCIMScopedClientCredentialTokenAllowsAccess() throws Exception {

    String response = mvc
      .perform(post(TOKEN_ENDPOINT).with(httpBasic(SCIM_CLIENT_RW_ID, SCIM_CLIENT_RW_SECRET))
        .param("grant_type", CLIENT_CREDENTIALS_GRANT_TYPE)
        .param("scope", "scim:read scim:write"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.scope", containsString("scim:read")))
      .andExpect(jsonPath("$.scope", containsString("scim:write")))
      .andReturn()
      .getResponse()
      .getContentAsString();

    String accessTokenSCIM = mapper.readTree(response).get("access_token").asText();

    String scimAuthorizationHeader = String.format("Bearer %s", accessTokenSCIM);

    mvc.perform(get("/scim/Users").header("Authorization", scimAuthorizationHeader))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.startIndex", equalTo(1)))
      .andExpect(jsonPath("$.Resources[1].userName", equalTo("test")));

    mvc.perform(get("/scim/Users/" + TEST_UUID).header("Authorization", scimAuthorizationHeader))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.userName", equalTo("test")));

    mvc.perform(delete("/scim/Users/" + TEST_UUID).header("Authorization", scimAuthorizationHeader))
      .andExpect(status().isNoContent());

    mvc.perform(get("/scim/Groups").header("Authorization", scimAuthorizationHeader))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.startIndex", equalTo(1)))
      .andExpect(jsonPath("$.Resources[0].displayName", equalTo("Production")));

    mvc
      .perform(get("/scim/Groups/" + PRODUCTION_GROUP_UUID).header("Authorization",
          scimAuthorizationHeader))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.displayName", equalTo("Production")));

    mvc
      .perform(delete("/scim/Groups/" + PRODUCTION_GROUP_UUID).header("Authorization",
          scimAuthorizationHeader))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.detail", equalTo("Group is not empty")));
  }

  @Test
  @WithAnonymousUser
  void testAdminScopedClientCredentialTokenAllowsAccess() throws Exception {

    String response = mvc
      .perform(post(TOKEN_ENDPOINT).with(httpBasic(ADMIN_CLIENT_ID, ADMIN_CLIENT_SECRET))
        .param("grant_type", CLIENT_CREDENTIALS_GRANT_TYPE)
        .param("scope", "iam:admin.read iam:admin.write"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.scope", containsString("iam:admin.read")))
      .andExpect(jsonPath("$.scope", containsString("iam:admin.write")))
      .andReturn()
      .getResponse()
      .getContentAsString();

    String accessTokenAdmin = mapper.readTree(response).get("access_token").asText();

    String adminAuthorizationHeader = String.format("Bearer %s", accessTokenAdmin);

    mvc
      .perform(get("/iam/api/clients/" + ADMIN_CLIENT_ID).header("Authorization",
          adminAuthorizationHeader))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.client_id", equalTo(ADMIN_CLIENT_ID)));

    mvc
      .perform(delete("/iam/api/clients/" + ADMIN_CLIENT_ID).header("Authorization",
          adminAuthorizationHeader))
      .andExpect(status().isNoContent());

  }
}
