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

import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.HttpHeaders;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;

@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK,
    properties = {"iam.protected-resources[0].id=data-api",
        "iam.protected-resources[0].resource=https://data.example.org/api",
        "iam.protected-resources[0].scopes=storage.read:/,storage.modify:/",
        "iam.protected-resources[0].name=Example data API",
        "iam.protected-resources[0].documentation=https://data.example.org/docs",
        "iam.protected-resources[1].id=minimal",
        "iam.protected-resources[1].resource=https://minimal.example.org"})
@AutoConfigureMockMvc
@Transactional
@ActiveProfiles({"h2-test"})
class ProtectedResourceMetadataTests {

  private static final String IAM_METADATA = "/.well-known/oauth-protected-resource";
  private static final String AS_METADATA = "/.well-known/oauth-authorization-server";
  private static final String RESOURCE_METADATA_PARAM =
      "resource_metadata=\"http://localhost:8080/.well-known/oauth-protected-resource\"";

  @Autowired
  private MockMvc mvc;

  @Autowired
  private ObjectMapper mapper;

  @Test
  void testIamMetadata() throws Exception {
    // @formatter:off
    mvc.perform(get(IAM_METADATA).header(HttpHeaders.ORIGIN, "http://example.org"))
      .andExpect(status().isOk())
      .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "*"))
      .andExpect(jsonPath("$.resource").value("http://localhost:8080"))
      .andExpect(jsonPath("$.authorization_servers", contains("http://localhost:8080/")))
      .andExpect(jsonPath("$.bearer_methods_supported", contains("header")))
      .andExpect(jsonPath("$.scopes_supported", hasItem("openid")))
      .andExpect(jsonPath("$.resource_policy_uri").value("http://localhost:8080/about"));
    // @formatter:on
  }

  @Test
  void testHostedMetadata() throws Exception {
    // @formatter:off
    mvc.perform(get("/protected-resource-metadata/data-api"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.resource").value("https://data.example.org/api"))
      .andExpect(jsonPath("$.authorization_servers", contains("http://localhost:8080/")))
      .andExpect(jsonPath("$.scopes_supported", contains("storage.read:/", "storage.modify:/")))
      .andExpect(jsonPath("$.bearer_methods_supported", contains("header")))
      .andExpect(jsonPath("$.resource_name").value("Example data API"))
      .andExpect(jsonPath("$.resource_documentation").value("https://data.example.org/docs"))
      .andExpect(jsonPath("$.resource_policy_uri").doesNotExist());

    mvc.perform(get("/protected-resource-metadata/minimal"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.scopes_supported").doesNotExist());

    mvc.perform(get("/protected-resource-metadata/unknown"))
      .andExpect(status().isNotFound());
    // @formatter:on
  }

  @Test
  void testDiscoveryDocumentsListProtectedResources() throws Exception {
    for (String endpoint : new String[] {AS_METADATA, "/.well-known/openid-configuration"}) {
      mvc.perform(get(endpoint).header(HttpHeaders.ORIGIN, "http://example.org"))
        .andExpect(status().isOk())
        .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "*"))
        .andExpect(jsonPath("$.issuer").value("http://localhost:8080/"))
        .andExpect(jsonPath("$.token_endpoint").value("http://localhost:8080/token"))
        .andExpect(jsonPath("$.protected_resources", contains("http://localhost:8080",
            "https://data.example.org/api", "https://minimal.example.org")));
    }
  }

  @Test
  void testChallengesAdvertiseResourceMetadata() throws Exception {
    mvc.perform(get("/scim/Users").header(HttpHeaders.AUTHORIZATION, "Bearer not-a-token"))
      .andExpect(status().isUnauthorized())
      .andExpect(
          header().string(HttpHeaders.WWW_AUTHENTICATE, containsString(RESOURCE_METADATA_PARAM)));

    mvc.perform(get("/userinfo"))
      .andExpect(status().isUnauthorized())
      .andExpect(
          header().string(HttpHeaders.WWW_AUTHENTICATE, containsString(RESOURCE_METADATA_PARAM)));
  }

  @Test
  void testTokenEndpointChallengeHasNoResourceMetadata() throws Exception {
    mvc
      .perform(post("/token").with(httpBasic("unknown-client", "wrong-secret"))
        .param("grant_type", "client_credentials"))
      .andExpect(status().isUnauthorized())
      .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE,
          not(containsString("resource_metadata"))));
  }

  @Test
  @WithMockUser(roles = "ADMIN")
  void testResourcesFromApplicationConfigAreNotReloadable() throws Exception {
    mvc.perform(post("/iam/api/protected-resources/reload").with(csrf()))
      .andExpect(status().isConflict());
  }

  @Test
  void testTokenForAnotherResourceIsAcceptedByDefault() throws Exception {
    String response = mvc
      .perform(post("/token").param("grant_type", "password")
        .param("client_id", "password-grant")
        .param("client_secret", "secret")
        .param("username", "test")
        .param("password", "password")
        .param("scope", "openid profile")
        .param("resource", "https://data.example.org/api"))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();
    String accessToken = mapper.readTree(response).get("access_token").asText();

    mvc.perform(get("/userinfo").header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
      .andExpect(status().isOk());
  }
}
