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

import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
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
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.core.web.wellknown.ProtectedResourceMetadataEndpoint;

@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Transactional
@ActiveProfiles({"h2-test"})
class ProtectedResourceMetadataEndpointTests {

  private static final String ENDPOINT =
      "/" + ProtectedResourceMetadataEndpoint.PROTECTED_RESOURCE_URL;

  private static final String RESOURCE_METADATA_PARAM =
      "resource_metadata=\"http://localhost:8080/.well-known/oauth-protected-resource\"";

  @Autowired
  private MockMvc mvc;

  @Test
  void testMetadataDocument() throws Exception {

    // @formatter:off
    mvc.perform(get(ENDPOINT))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.resource").value("http://localhost:8080"))
      .andExpect(jsonPath("$.authorization_servers[0]").value("http://localhost:8080/"))
      .andExpect(jsonPath("$.bearer_methods_supported[0]").value("header"))
      .andExpect(jsonPath("$.scopes_supported", hasItem("openid")))
      .andExpect(jsonPath("$.resource_policy_uri").value("http://localhost:8080/about"));
    // @formatter:on
  }

  @Test
  void testMetadataIsPublicAndCorsEnabled() throws Exception {

    mvc.perform(get(ENDPOINT).header(HttpHeaders.ORIGIN, "http://example.org"))
      .andExpect(status().isOk())
      .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "*"));
  }

  @Test
  void testScimChallengeAdvertisesResourceMetadata() throws Exception {

    mvc.perform(get("/scim/Users").header(HttpHeaders.AUTHORIZATION, "Bearer not-a-token"))
      .andExpect(status().isUnauthorized())
      .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("Bearer")))
      .andExpect(
          header().string(HttpHeaders.WWW_AUTHENTICATE, containsString(RESOURCE_METADATA_PARAM)));
  }

  @Test
  void testUserinfoChallengeAdvertisesResourceMetadata() throws Exception {

    mvc.perform(get("/userinfo"))
      .andExpect(status().isUnauthorized())
      .andExpect(
          header().string(HttpHeaders.WWW_AUTHENTICATE, containsString(RESOURCE_METADATA_PARAM)));
  }

  @Test
  void testTokenEndpointChallengeDoesNotAdvertiseResourceMetadata() throws Exception {

    mvc
      .perform(post("/token").with(httpBasic("unknown-client", "wrong-secret"))
        .param("grant_type", "client_credentials"))
      .andExpect(status().isUnauthorized())
      .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE,
          not(containsString("resource_metadata"))));
  }
}
