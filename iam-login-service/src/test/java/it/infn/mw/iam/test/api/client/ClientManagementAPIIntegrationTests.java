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
import static org.junit.Assert.assertTrue;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultMatcher;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.client.management.ClientManagementAPIController;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.test.api.TestSupport;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.oauth.client_registration.ClientRegistrationTestSupport.ClientJsonStringBuilder;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class, CoreControllerTestSupport.class})
public class ClientManagementAPIIntegrationTests extends TestSupport {

  @Autowired
  private MockMvc mvc;

  @Autowired
  private ObjectMapper mapper;

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;


  @BeforeEach
  public void setup() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @AfterEach
  public void teardown() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  private void clientManagementFailsWithResponseForClient(ResultMatcher response, String clientId)
      throws Exception {
    String clientJson = ClientJsonStringBuilder.builder().build();
    mvc.perform(get(ClientManagementAPIController.ENDPOINT)).andExpect(response);
    mvc
      .perform(post(ClientManagementAPIController.ENDPOINT).contentType(APPLICATION_JSON)
        .content(clientJson))
      .andExpect(response);
    mvc
      .perform(
          put(ClientManagementAPIController.ENDPOINT + "/" + clientId).contentType(APPLICATION_JSON)
            .content(clientJson))
      .andExpect(response);
    mvc.perform(delete(ClientManagementAPIController.ENDPOINT + "/" + clientId))
      .andExpect(response);
  }

  private void paginatedGetClientsTest() throws Exception {
    mvc.perform(get(ClientManagementAPIController.ENDPOINT))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults").value(18))
      .andExpect(jsonPath("$.itemsPerPage").value(10))
      .andExpect(jsonPath("$.startIndex").value(1))
      .andExpect(jsonPath("$.Resources", hasSize(10)))
      .andExpect(jsonPath("$.Resources[0].client_id").value("admin-client-ro"));

    mvc.perform(get(ClientManagementAPIController.ENDPOINT).param("startIndex", "11"))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults").value(18))
      .andExpect(jsonPath("$.itemsPerPage").value(8))
      .andExpect(jsonPath("$.startIndex").value(11))
      .andExpect(jsonPath("$.Resources", hasSize(8)))
      .andExpect(jsonPath("$.Resources[0].client_id").value("public-dc-client"));
  }

  @Test
  @WithAnonymousUser
  public void clientManagementRequiresAuthenticatedUser() throws Exception {
    clientManagementFailsWithResponseForClient(UNAUTHORIZED, "client");
  }

  @Test
  @WithMockUser(username = "test", roles = "USER")
  public void clientManagementIsForbiddenForUsers() throws Exception {
    clientManagementFailsWithResponseForClient(FORBIDDEN, "client");
  }

  @Test
  @WithMockOAuthUser(user = "test", scopes = {"openid"})
  public void clientManagementIsForbiddenWithoutAdminScopes() throws Exception {
    clientManagementFailsWithResponseForClient(FORBIDDEN, "client");
  }

  @Test
  @WithMockOAuthUser(user = "test", scopes = {"iam:admin.read"})
  public void paginatedGetClientsWorksWithScopes() throws Exception {
    paginatedGetClientsTest();
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void paginatedGetClientsWorksAsAdmin() throws Exception {
    paginatedGetClientsTest();
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
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
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
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

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void setTokenLifetimesWorks() throws Exception {

    String clientJson = ClientJsonStringBuilder.builder()
      .scopes("openid")
      .accessTokenValiditySeconds(null)
      .refreshTokenValiditySeconds(null)
      .build();

    String responseJson = mvc
      .perform(post(ClientManagementAPIController.ENDPOINT).contentType(APPLICATION_JSON)
        .content(clientJson))
      .andExpect(CREATED)
      .andReturn()
      .getResponse()
      .getContentAsString();

    RegisteredClientDTO client = mapper.readValue(responseJson, RegisteredClientDTO.class);
    assertTrue(client.getAccessTokenValiditySeconds().equals(3600));
    assertTrue(client.getRefreshTokenValiditySeconds().equals(108000));

    clientJson = ClientJsonStringBuilder.builder()
      .scopes("openid")
      .accessTokenValiditySeconds(0)
      .refreshTokenValiditySeconds(0)
      .build();

    responseJson = mvc
      .perform(post(ClientManagementAPIController.ENDPOINT).contentType(APPLICATION_JSON)
        .content(clientJson))
      .andExpect(CREATED)
      .andReturn()
      .getResponse()
      .getContentAsString();

    client = mapper.readValue(responseJson, RegisteredClientDTO.class);
    assertTrue(client.getAccessTokenValiditySeconds().equals(0));
    assertTrue(client.getRefreshTokenValiditySeconds().equals(0));

    clientJson = ClientJsonStringBuilder.builder()
      .scopes("openid")
      .accessTokenValiditySeconds(10)
      .refreshTokenValiditySeconds(10)
      .build();

    responseJson = mvc
      .perform(post(ClientManagementAPIController.ENDPOINT).contentType(APPLICATION_JSON)
        .content(clientJson))
      .andExpect(CREATED)
      .andReturn()
      .getResponse()
      .getContentAsString();

    client = mapper.readValue(responseJson, RegisteredClientDTO.class);
    assertTrue(client.getAccessTokenValiditySeconds().equals(10));
    assertTrue(client.getRefreshTokenValiditySeconds().equals(10));

  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void negativeTokenLifetimesNotAllowed() throws Exception {

    String clientJson =
        ClientJsonStringBuilder.builder().scopes("openid").accessTokenValiditySeconds(-1).build();

    mvc
      .perform(post(ClientManagementAPIController.ENDPOINT).contentType(APPLICATION_JSON)
        .content(clientJson))
      .andExpect(BAD_REQUEST)
      .andExpect(jsonPath("$.error", containsString("must be greater than or equal to 0")));

    clientJson =
        ClientJsonStringBuilder.builder().scopes("openid").refreshTokenValiditySeconds(-1).build();

    mvc
      .perform(post(ClientManagementAPIController.ENDPOINT).contentType(APPLICATION_JSON)
        .content(clientJson))
      .andExpect(BAD_REQUEST)
      .andExpect(jsonPath("$.error", containsString("must be greater than or equal to 0")));
  }
}
