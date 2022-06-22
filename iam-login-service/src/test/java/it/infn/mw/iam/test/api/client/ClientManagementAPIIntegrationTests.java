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

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.client.management.ClientManagementAPIController;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.test.api.TestSupport;
import it.infn.mw.iam.test.oauth.client_registration.ClientRegistrationTestSupport.ClientJsonStringBuilder;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@IamMockMvcIntegrationTest
@WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
@SpringBootTest(classes = {IamLoginService.class})
public class ClientManagementAPIIntegrationTests extends TestSupport {

  @Autowired
  private MockMvc mvc;

  @Autowired
  private ObjectMapper mapper;

  @Test
  @WithAnonymousUser
  public void clientManagementRequiresAuthenticatedUser() throws Exception {

    String clientJson = ClientJsonStringBuilder.builder().build();
    mvc.perform(get(ClientManagementAPIController.ENDPOINT)).andExpect(UNAUTHORIZED);
    mvc
      .perform(post(ClientManagementAPIController.ENDPOINT).contentType(APPLICATION_JSON)
        .content(clientJson))
      .andExpect(UNAUTHORIZED);
    mvc
      .perform(put(ClientManagementAPIController.ENDPOINT + "/client").contentType(APPLICATION_JSON)
        .content(clientJson))
      .andExpect(UNAUTHORIZED);
    mvc.perform(delete(ClientManagementAPIController.ENDPOINT + "/client")).andExpect(UNAUTHORIZED);
  }

  @Test
  @WithMockUser(username = "test", roles = "USER")
  public void clientManagementRequiresAdminUser() throws Exception {
    String clientJson = ClientJsonStringBuilder.builder().build();
    mvc.perform(get(ClientManagementAPIController.ENDPOINT)).andExpect(FORBIDDEN);
    mvc
      .perform(post(ClientManagementAPIController.ENDPOINT).contentType(APPLICATION_JSON)
        .content(clientJson))
      .andExpect(FORBIDDEN);
    mvc
      .perform(put(ClientManagementAPIController.ENDPOINT + "/client").contentType(APPLICATION_JSON)
        .content(clientJson))
      .andExpect(FORBIDDEN);
    mvc.perform(delete(ClientManagementAPIController.ENDPOINT + "/client")).andExpect(FORBIDDEN);
  }


  @Test
  public void paginatedGetClientsWorks() throws Exception {
    mvc.perform(get(ClientManagementAPIController.ENDPOINT))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults").value(16))
      .andExpect(jsonPath("$.itemsPerPage").value(10))
      .andExpect(jsonPath("$.startIndex").value(1))
      .andExpect(jsonPath("$.Resources", hasSize(10)))
      .andExpect(jsonPath("$.Resources[0].client_id").value("client"));

    mvc.perform(get(ClientManagementAPIController.ENDPOINT).param("startIndex", "11"))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults").value(16))
      .andExpect(jsonPath("$.itemsPerPage").value(6))
      .andExpect(jsonPath("$.startIndex").value(11))
      .andExpect(jsonPath("$.Resources", hasSize(6)))
      .andExpect(jsonPath("$.Resources[0].client_id").value("scim-client-ro"));
  }

  @Test
  public void clientRemovalWorks() throws Exception {

    mvc.perform(get(ClientManagementAPIController.ENDPOINT + "/client"))
      .andExpect(OK)
      .andExpect(jsonPath("$.client_id").value("client"));

    mvc.perform(delete(ClientManagementAPIController.ENDPOINT + "/client")).andExpect(NO_CONTENT);

    mvc.perform(get(ClientManagementAPIController.ENDPOINT + "/client"))
      .andExpect(NOT_FOUND)
      .andExpect(jsonPath("$.error", containsString("Client not found")));
  }

  @Test
  public void ratRotationWorks() throws Exception {

    String clientJson = ClientJsonStringBuilder.builder().scopes("openid").build();

    String responseJson = mvc
      .perform(post(ClientManagementAPIController.ENDPOINT).contentType(APPLICATION_JSON)
        .content(clientJson))
      .andExpect(CREATED)
      .andReturn()
      .getResponse()
      .getContentAsString();

    RegisteredClientDTO client = mapper.readValue(responseJson, RegisteredClientDTO.class);
    assertThat(client.getRegistrationAccessToken(), nullValue());

    final String url =
        String.format("%s/%s/rat", ClientManagementAPIController.ENDPOINT, client.getClientId());

    responseJson = mvc.perform(post(url)).andReturn().getResponse().getContentAsString();
    client = mapper.readValue(responseJson, RegisteredClientDTO.class);
    assertThat(client.getRegistrationAccessToken(), notNullValue());
  }
}
