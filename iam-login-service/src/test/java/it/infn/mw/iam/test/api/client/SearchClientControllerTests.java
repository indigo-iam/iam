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
package it.infn.mw.iam.test.api.client;

import static it.infn.mw.iam.api.client.search.SearchClientController.ENDPOINT;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.MockMvcPrint;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@SpringBootTest(classes = {IamLoginService.class, CoreControllerTestSupport.class})
@AutoConfigureMockMvc(printOnlyOnFailure = true, print = MockMvcPrint.LOG_DEBUG)
class SearchClientControllerTests {

  @Autowired
  private MockMvc mvc;

  @Autowired
  private ObjectMapper mapper;

  @Autowired
  private MockOAuth2Filter filter;

  @AfterEach
  void tearDown() {
    filter.cleanupSecurityContext();
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"}, scopes = "iam:admin.read")
  void searchForPublicClientByName() throws Exception {

    ListResponseDTO<RegisteredClientDTO> response = mapper.readValue(
        mvc.perform(get(ENDPOINT).param("search", "Public client").param("searchType", "name"))
          .andExpect(status().isOk())
          .andReturn()
          .getResponse()
          .getContentAsString(),
        new TypeReference<ListResponseDTO<RegisteredClientDTO>>() {});
    assertEquals(1, response.getTotalResults());
    assertEquals("Public client", response.getResources().get(0).getClientName());
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"}, scopes = "iam:admin.read")
  void clientSearchIsCaseInsensitive() throws Exception {

    ListResponseDTO<RegisteredClientDTO> response =
        mapper
          .readValue(
              mvc.perform(get(ENDPOINT).param("search", "Test Client").param("searchType", "name"))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString(),
              new TypeReference<ListResponseDTO<RegisteredClientDTO>>() {});

    assertEquals(2, response.getTotalResults());

    List<String> names =
        response.getResources().stream().map(RegisteredClientDTO::getClientName).toList();

    assertTrue(names.contains("Test Client"));
    assertTrue(names.contains("Registration service test client"));
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"}, scopes = "iam:admin.read")
  void searchForClientsByNamePrefix() throws Exception {

    ListResponseDTO<RegisteredClientDTO> response = mapper
      .readValue(mvc.perform(get(ENDPOINT).param("search", "Adm").param("searchType", "name"))
        .andExpect(status().isOk())
        .andReturn()
        .getResponse()
        .getContentAsString(), new TypeReference<ListResponseDTO<RegisteredClientDTO>>() {});
    assertEquals(2, response.getTotalResults());
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"}, scopes = "iam:admin.read")
  void searchForNonExistingClient() throws Exception {

    ListResponseDTO<RegisteredClientDTO> response = mapper
      .readValue(mvc.perform(get(ENDPOINT).param("search", "ghost").param("searchType", "name"))
        .andExpect(status().isOk())
        .andReturn()
        .getResponse()
        .getContentAsString(), new TypeReference<ListResponseDTO<RegisteredClientDTO>>() {});
    assertEquals(0, response.getTotalResults());
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"}, scopes = "iam:admin.read")
  void searchForAdminClientsByScope() throws Exception {

    ListResponseDTO<RegisteredClientDTO> response = mapper
      .readValue(mvc.perform(get(ENDPOINT).param("search", "admin").param("searchType", "scope"))
        .andExpect(status().isOk())
        .andReturn()
        .getResponse()
        .getContentAsString(), new TypeReference<ListResponseDTO<RegisteredClientDTO>>() {});
    assertEquals(5, response.getTotalResults());
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"}, scopes = "iam:admin.read")
  void searchClientsWithAdminUserAndAdminScope() throws Exception {

    mvc.perform(get(ENDPOINT).param("search", "Admin").param("searchType", "name"))
      .andExpect(status().isOk());
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_ADMIN"})
  void searchClientsWithAdminUserWithoutAdminScope() throws Exception {

    mvc.perform(get(ENDPOINT).param("search", "Admin").param("searchType", "name"))
      .andExpect(status().isForbidden());
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN"})
  void searchClientsWithAdminUser() throws Exception {

    mvc.perform(get(ENDPOINT).param("search", "Admin").param("searchType", "name"))
      .andExpect(status().isOk());
  }

  @Test
  @WithMockUser(username = "test", roles = {"USER"})
  void searchClientsWithTestUser() throws Exception {

    mvc.perform(get(ENDPOINT).param("search", "Admin").param("searchType", "name"))
      .andExpect(status().isForbidden());
  }
}
