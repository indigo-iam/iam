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

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
public class TokenEndpointClientAuthenticationTests {

  private static final String TOKEN_ENDPOINT = "/token";
  private static final String GRANT_TYPE = "client_credentials";
  private static final String SCOPE = "read-tasks";
  private static final String SCOPE_SUBSET = "openid";

  private static final String TEST_USER_UUID = "80e5fb8d-b7c8-451a-89ba-346ae278a66f";
  private static final String PRODUCTION_GROUP_UUID = "c617d586-54e6-411d-8e38-64967798fa8a";

  @Autowired
  private MockMvc mvc;

  @Autowired
  private ObjectMapper mapper;

  @Test
  public void testTokenEndpointFormClientAuthentication() throws Exception {

    String clientId = "post-client";
    String clientSecret = "secret";

    // @formatter:off
    mvc.perform(post(TOKEN_ENDPOINT)
        .param("grant_type", GRANT_TYPE)
        .param("client_id", clientId)
        .param("client_secret", clientSecret)
        .param("scope", SCOPE))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.scope", equalTo(SCOPE)));
    // @formatter:on
  }

  @Test
  public void testTokenEndpointFormClientAuthenticationInvalidCredentials() throws Exception {

    String clientId = "post-client";
    String clientSecret = "wrong-password";

    // @formatter:off
    mvc.perform(post(TOKEN_ENDPOINT)
        .param("grant_type", GRANT_TYPE)
        .param("client_id", clientId)
        .param("client_secret", clientSecret)
        .param("scope", SCOPE))
      .andExpect(status().isUnauthorized())
      .andExpect(jsonPath("$.error", equalTo("invalid_client")))
      .andExpect(jsonPath("$.error_description", equalTo("Bad client credentials")));
    // @formatter:on
  }

  @Test
  public void testTokenEndpointFormClientAuthenticationUnknownClient() throws Exception {

    String clientId = "unknown-client";
    String clientSecret = "password";

    // @formatter:off
    mvc.perform(post(TOKEN_ENDPOINT)
        .param("grant_type", GRANT_TYPE)
        .param("client_id", clientId)
        .param("client_secret", clientSecret)
        .param("scope", SCOPE))
      .andExpect(status().isUnauthorized())
      .andExpect(jsonPath("$.error", equalTo("invalid_client")))
      .andExpect(jsonPath("$.error_description", equalTo("Bad client credentials")));
    // @formatter:on
  }

  @Test
  public void testTokenEndpointBasicClientAuthentication() throws Exception {

    String clientId = "post-client";
    String clientSecret = "secret";

    // @formatter:off
    mvc.perform(post(TOKEN_ENDPOINT)
        .with(httpBasic(clientId, clientSecret))
        .param("grant_type", GRANT_TYPE)
        .param("scope", SCOPE))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.scope", equalTo(SCOPE)));
    // @formatter:on
  }

  @Test
  public void testTokenEndpointOptionsMethodAllowed() throws Exception {
    mvc.perform(options(TOKEN_ENDPOINT)).andExpect(status().isOk());
  }

  @Test
  @WithAnonymousUser
  public void testInsufficientScopedClientCredentialTokenForbidsAccess() throws Exception {

    String clientId = "scim-client-rw";
    String clientSecret = "secret";

    String response = mvc
      .perform(post(TOKEN_ENDPOINT).with(httpBasic(clientId, clientSecret))
        .param("grant_type", GRANT_TYPE)
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

    mvc
      .perform(
          get("/scim/Users/" + TEST_USER_UUID).header("Authorization", scimAuthorizationHeader))
      .andExpect(status().isForbidden());

    mvc
      .perform(
          delete("/scim/Users/" + TEST_USER_UUID).header("Authorization", scimAuthorizationHeader))
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
  public void testSCIMScopedClientCredentialTokenAllowsAccess() throws Exception {

    String clientId = "scim-client-rw";
    String clientSecret = "secret";

    String response = mvc
      .perform(post(TOKEN_ENDPOINT).with(httpBasic(clientId, clientSecret))
        .param("grant_type", GRANT_TYPE)
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

    mvc
      .perform(
          get("/scim/Users/" + TEST_USER_UUID).header("Authorization", scimAuthorizationHeader))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.userName", equalTo("test")));

    mvc
      .perform(
          delete("/scim/Users/" + TEST_USER_UUID).header("Authorization", scimAuthorizationHeader))
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
  public void testAdminScopedClientCredentialTokenAllowsAccess() throws Exception {

    String clientId = "admin-client-rw";
    String clientSecret = "secret";

    String response = mvc
      .perform(post(TOKEN_ENDPOINT).with(httpBasic(clientId, clientSecret))
        .param("grant_type", GRANT_TYPE)
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
      .perform(
          get("/iam/api/clients/" + clientId).header("Authorization", adminAuthorizationHeader))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.client_id", equalTo(clientId)));

    mvc
      .perform(
          delete("/iam/api/clients/" + clientId).header("Authorization", adminAuthorizationHeader))
      .andExpect(status().isNoContent());

  }
}
