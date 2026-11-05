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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
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

@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK,
    properties = {"iam.protected-resources[0].id=data-api",
        "iam.protected-resources[0].resource=https://data.example.org/api"})
@AutoConfigureMockMvc
@Transactional
@ActiveProfiles({"h2-test"})
class AuthorizationServerMetadataTests {

  private static final String AS_METADATA = "/.well-known/oauth-authorization-server";
  private static final String OIDC_DISCOVERY = "/.well-known/openid-configuration";

  @Autowired
  private MockMvc mvc;

  @Test
  void testAuthorizationServerMetadata() throws Exception {

    // @formatter:off
    mvc.perform(get(AS_METADATA))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.issuer").value("http://localhost:8080/"))
      .andExpect(jsonPath("$.authorization_endpoint").value("http://localhost:8080/authorize"))
      .andExpect(jsonPath("$.token_endpoint").value("http://localhost:8080/token"))
      .andExpect(jsonPath("$.jwks_uri").value("http://localhost:8080/jwk"))
      .andExpect(jsonPath("$.response_types_supported").isArray())
      .andExpect(jsonPath("$.protected_resources",
          contains("http://localhost:8080", "https://data.example.org/api")));
    // @formatter:on
  }

  @Test
  void testOpenIdDiscoveryListsProtectedResources() throws Exception {

    mvc.perform(get(OIDC_DISCOVERY))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.protected_resources",
          contains("http://localhost:8080", "https://data.example.org/api")));
  }

  @Test
  void testAuthorizationServerMetadataIsPublicAndCorsEnabled() throws Exception {

    mvc.perform(get(AS_METADATA).header(HttpHeaders.ORIGIN, "http://example.org"))
      .andExpect(status().isOk())
      .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "*"));
  }
}
