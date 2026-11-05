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
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

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
class HostedProtectedResourceMetadataTests {

  @Autowired
  private MockMvc mvc;

  @Test
  void testConfiguredResourceMetadata() throws Exception {

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
    // @formatter:on
  }

  @Test
  void testMinimalResourceOmitsEmptyFields() throws Exception {

    mvc.perform(get("/protected-resource-metadata/minimal"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.resource").value("https://minimal.example.org"))
      .andExpect(jsonPath("$.scopes_supported").doesNotExist())
      .andExpect(jsonPath("$.bearer_methods_supported", contains("header")));
  }

  @Test
  void testUnknownResourceIsNotFound() throws Exception {

    mvc.perform(get("/protected-resource-metadata/unknown")).andExpect(status().isNotFound());
  }

  @Test
  @WithMockUser(roles = "ADMIN")
  void testResourcesFromApplicationConfigAreNotReloadable() throws Exception {

    mvc.perform(post("/iam/api/protected-resources/reload").with(csrf()))
      .andExpect(status().isConflict());
  }

  @Test
  void testIamOwnMetadataIsUnchanged() throws Exception {

    mvc.perform(get("/.well-known/oauth-protected-resource"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.resource").value("http://localhost:8080"));
  }
}
