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
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.test.context.TestSecurityContextHolder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.protected_resources.ProtectedResourcesController;

@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK,
    properties = "iam.resource-indicators.restrict-to-protected-resources=true")
@AutoConfigureMockMvc
@Transactional
@ActiveProfiles({"h2-test"})
class ProtectedResourcesReloadTests {

  private static final String DATA_API = """
      protected-resources:
        - id: data-api
          resource: https://data.example.org/api
      """;

  private static final String COMPUTE_API = """
      protected-resources:
        - id: compute-api
          resource: https://compute.example.org
      """;

  private static final Path FILE;

  static {
    try {
      FILE = Files.createTempFile("protected-resources", ".yml");
      Files.writeString(FILE, DATA_API);
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  private static final String LIST = ProtectedResourcesController.ENDPOINT;
  private static final String RELOAD = ProtectedResourcesController.ENDPOINT + "/reload";

  @DynamicPropertySource
  static void protectedResourcesFile(DynamicPropertyRegistry registry) {
    registry.add("iam.protected-resources-file.path", FILE::toString);
  }

  @Autowired
  private MockMvc mvc;

  @AfterEach
  void restoreFile() throws Exception {
    Files.writeString(FILE, DATA_API);
    mvc.perform(post(RELOAD).with(csrf()).with(user("admin").roles("ADMIN", "USER")))
      .andExpect(status().isOk());
  }

  @Test
  @WithMockUser(roles = "ADMIN")
  void testAdminCanListResources() throws Exception {
    mvc.perform(get(LIST))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$[0].id").value("data-api"))
      .andExpect(jsonPath("$[0].resource").value("https://data.example.org/api"))
      .andExpect(jsonPath("$[0].metadata_url")
        .value("http://localhost:8080/protected-resource-metadata/data-api"));
  }

  @Test
  @WithMockUser(roles = "USER")
  void testUserCannotListOrReload() throws Exception {
    mvc.perform(get(LIST)).andExpect(status().isForbidden());
    mvc.perform(post(RELOAD).with(csrf())).andExpect(status().isForbidden());
  }

  @Test
  void testAnonymousCannotReload() throws Exception {
    mvc.perform(post(RELOAD).with(csrf())).andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockUser(roles = "ADMIN")
  void testReloadAppliesEverywhere() throws Exception {

    Files.writeString(FILE, COMPUTE_API);

    mvc.perform(post(RELOAD).with(csrf()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$[*].id", contains("compute-api")));

    mvc.perform(get("/protected-resource-metadata/compute-api"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.resource").value("https://compute.example.org"));
    mvc.perform(get("/protected-resource-metadata/data-api")).andExpect(status().isNotFound());

    mvc.perform(get("/.well-known/oauth-authorization-server"))
      .andExpect(jsonPath("$.protected_resources",
          contains("http://localhost:8080", "https://compute.example.org")));

    // The token requests are authenticated as the client, not the admin user.
    TestSecurityContextHolder.clearContext();

    mvc.perform(post("/token").param("grant_type", "client_credentials")
      .param("client_id", "client-cred")
      .param("client_secret", "secret")
      .param("resource", "https://compute.example.org")).andExpect(status().isOk());

    mvc.perform(post("/token").param("grant_type", "client_credentials")
      .param("client_id", "client-cred")
      .param("client_secret", "secret")
      .param("resource", "https://data.example.org/api"))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error").value("invalid_target"));
  }

  @Test
  @WithMockUser(roles = "ADMIN")
  void testInvalidReloadKeepsCurrentResources() throws Exception {

    Files.writeString(FILE, "protected-resources:\n  - id: a\n    resource: not a url\n");

    mvc.perform(post(RELOAD).with(csrf()))
      .andExpect(status().isBadRequest())
      .andExpect(content().string(containsString("Invalid iam.protected-resources 'a'")));

    mvc.perform(get("/protected-resource-metadata/data-api")).andExpect(status().isOk());
  }
}
