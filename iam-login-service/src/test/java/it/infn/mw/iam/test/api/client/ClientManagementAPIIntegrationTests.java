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

import java.util.Optional;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultMatcher;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.client.management.ClientManagementAPIController;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.api.tokens.Constants;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.test.api.TestSupport;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.oauth.client_registration.ClientRegistrationTestSupport.ClientJsonStringBuilder;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class, CoreControllerTestSupport.class})
class ClientManagementAPIIntegrationTests extends TestSupport {

  public static final String[] REFRESH_SCOPES = {"openid", "profile", "offline_access"};

  public static final String[] ACCESS_SCOPES = {"openid", "profile"};

  public static final String TEST_CLIENT_ID = "token-lookup-client";

  private static final String TESTUSER_USERNAME = "test_102";

  protected static final String REFRESH_TOKENS_BASE_PATH = Constants.REFRESH_TOKENS_ENDPOINT;

  protected static final String ACCESS_TOKENS_BASE_PATH = Constants.ACCESS_TOKENS_ENDPOINT;

  @Autowired
  private MockMvc mvc;

  @Autowired
  private ObjectMapper mapper;

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  @Autowired
  private IamClientRepository clientRepo;

  @Autowired
  private ClientDetailsEntityService clientDetailsService;


  @BeforeEach
  void setup() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @AfterEach
  void teardown() {
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
      .andExpect(jsonPath("$.totalResults").value(21))
      .andExpect(jsonPath("$.itemsPerPage").value(10))
      .andExpect(jsonPath("$.startIndex").value(1))
      .andExpect(jsonPath("$.Resources", hasSize(10)))
      .andExpect(jsonPath("$.Resources[0].client_id").value("admin-client-ro"));

    mvc.perform(get(ClientManagementAPIController.ENDPOINT).param("startIndex", "13"))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults").value(21))
      .andExpect(jsonPath("$.itemsPerPage").value(9))
      .andExpect(jsonPath("$.startIndex").value(13))
      .andExpect(jsonPath("$.Resources", hasSize(9)))
      .andExpect(jsonPath("$.Resources[0].client_id").value("public-dc-client"));
  }

  @Test
  @WithAnonymousUser
  void clientManagementRequiresAuthenticatedUser() throws Exception {
    clientManagementFailsWithResponseForClient(UNAUTHORIZED, "client");
  }

  @Test
  @WithMockUser(username = "test", roles = "USER")
  void clientManagementIsForbiddenForUsers() throws Exception {
    clientManagementFailsWithResponseForClient(FORBIDDEN, "client");
  }

  @Test
  @WithMockOAuthUser(user = "test", scopes = {"openid"})
  void clientManagementIsForbiddenWithoutAdminScopes() throws Exception {
    clientManagementFailsWithResponseForClient(FORBIDDEN, "client");
  }

  @Test
  @WithMockOAuthUser(user = "test", scopes = {"iam:admin.read"})
  void paginatedGetClientsWorksWithScopes() throws Exception {
    paginatedGetClientsTest();
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  void paginatedGetClientsWorksAsAdmin() throws Exception {
    paginatedGetClientsTest();
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  void clientRemovalWorks() throws Exception {

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
  void ratRotationWorks() throws Exception {

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
    assertThat(client.getClientSecret(), notNullValue());

    final String url =
        String.format("%s/%s/rat", ClientManagementAPIController.ENDPOINT, client.getClientId());

    String responseJson2 = mvc.perform(post(url)).andReturn().getResponse().getContentAsString();
    client = mapper.readValue(responseJson2, RegisteredClientDTO.class);
    assertThat(client.getClientSecret(), nullValue());
    assertThat(client.getRegistrationAccessToken(), notNullValue());
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  void testUpdateClientWithForbiddenParams() throws Exception {

    String clientJson = ClientJsonStringBuilder.builder().scopes("openid").build();

    String responseJson = mvc
      .perform(post(ClientManagementAPIController.ENDPOINT).contentType(APPLICATION_JSON)
        .content(clientJson))
      .andExpect(CREATED)
      .andReturn()
      .getResponse()
      .getContentAsString();

    RegisteredClientDTO clientDto = mapper.readValue(responseJson, RegisteredClientDTO.class);
    assertThat(clientDto.getClientSecret(), not(containsString("secret")));
    assertThat(clientDto.getClientSecret(), notNullValue());

    responseJson = mvc
      .perform(put(ClientManagementAPIController.ENDPOINT + "/" + clientDto.getClientId())
        .contentType("application/json")
        .content(mapper.writeValueAsString(clientDto)))
      .andExpect(status().is2xxSuccessful())
      .andReturn()
      .getResponse()
      .getContentAsString();
    RegisteredClientDTO clientUpdatedDto =
        mapper.readValue(responseJson, RegisteredClientDTO.class);
    assertThat(clientUpdatedDto.getClientSecret(), nullValue());
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  void setTokenLifetimesWorks() throws Exception {

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
    assertEquals(3600, client.getAccessTokenValiditySeconds());
    assertEquals(2592000, client.getRefreshTokenValiditySeconds());
    assertEquals(600, client.getIdTokenValiditySeconds());
    assertEquals(600, client.getDeviceCodeValiditySeconds());

    Optional<ClientDetailsEntity> clientDB = clientRepo.findByClientId(client.getClientId());
    assertEquals(client.getAccessTokenValiditySeconds(),
        clientDB.get().getAccessTokenValiditySeconds());
    assertEquals(client.getRefreshTokenValiditySeconds(),
        clientDB.get().getRefreshTokenValiditySeconds());
    assertEquals(client.getIdTokenValiditySeconds(), clientDB.get().getIdTokenValiditySeconds());
    assertEquals(client.getDeviceCodeValiditySeconds(),
        clientDB.get().getDeviceCodeValiditySeconds());

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
    assertEquals(3600, client.getAccessTokenValiditySeconds());
    assertEquals(0, client.getRefreshTokenValiditySeconds());

    clientDB = clientRepo.findByClientId(client.getClientId());
    assertEquals(client.getAccessTokenValiditySeconds(),
        clientDB.get().getAccessTokenValiditySeconds());
    assertEquals(client.getRefreshTokenValiditySeconds(),
        clientDB.get().getRefreshTokenValiditySeconds());
    assertEquals(client.getIdTokenValiditySeconds(), clientDB.get().getIdTokenValiditySeconds());
    assertEquals(client.getDeviceCodeValiditySeconds(),
        clientDB.get().getDeviceCodeValiditySeconds());

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
    assertEquals(10, client.getAccessTokenValiditySeconds());
    assertEquals(10, client.getRefreshTokenValiditySeconds());

    clientDB = clientRepo.findByClientId(client.getClientId());
    assertEquals(client.getAccessTokenValiditySeconds(),
        clientDB.get().getAccessTokenValiditySeconds());
    assertEquals(client.getRefreshTokenValiditySeconds(),
        clientDB.get().getRefreshTokenValiditySeconds());
    assertEquals(client.getIdTokenValiditySeconds(), clientDB.get().getIdTokenValiditySeconds());
    assertEquals(client.getDeviceCodeValiditySeconds(),
        clientDB.get().getDeviceCodeValiditySeconds());

  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  void negativeAccessTokenLifetimesSetToDefault() throws Exception {

    String clientJson =
        ClientJsonStringBuilder.builder().scopes("openid").accessTokenValiditySeconds(-1).build();

    mvc
      .perform(post(ClientManagementAPIController.ENDPOINT).contentType(APPLICATION_JSON)
        .content(clientJson))
      .andExpect(BAD_REQUEST)
      .andExpect(jsonPath("$.error", containsString("must be greater than or equal to 0")));
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  void negativeRefreshTokenLifetimesSetToInfinite() throws Exception {

    String clientJson =
        ClientJsonStringBuilder.builder().scopes("openid").refreshTokenValiditySeconds(-1).build();

    mvc
      .perform(post(ClientManagementAPIController.ENDPOINT).contentType(APPLICATION_JSON)
        .content(clientJson))
      .andExpect(BAD_REQUEST)
      .andExpect(jsonPath("$.error", containsString("must be greater than or equal to 0")));
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  void setClientEnableWorks() throws Exception {

    mvc.perform(get(ClientManagementAPIController.ENDPOINT + "/client"))
      .andExpect(OK)
      .andExpect(jsonPath("$.active").value(true));

    mvc.perform(patch(ClientManagementAPIController.ENDPOINT + "/{clientId}/enable", "client"))
      .andExpect(OK);

    mvc.perform(get(ClientManagementAPIController.ENDPOINT + "/client"))
      .andExpect(OK)
      .andExpect(jsonPath("$.active").value(true));
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  void setClientDisableWorks() throws Exception {

    mvc.perform(get(ClientManagementAPIController.ENDPOINT + "/client"))
      .andExpect(OK)
      .andExpect(jsonPath("$.active").value(true));

    mvc.perform(patch(ClientManagementAPIController.ENDPOINT + "/{clientId}/disable", "client"))
      .andExpect(OK);

    mvc.perform(get(ClientManagementAPIController.ENDPOINT + "/client"))
      .andExpect(OK)
      .andExpect(jsonPath("$.active").value(false));
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  void testClientRevokeAllRefreshTokensWorks() throws Exception {
    ClientDetailsEntity client = clientDetailsService.loadClientByClientId(TEST_CLIENT_ID);
    buildAccessToken(client, TESTUSER_USERNAME, REFRESH_SCOPES);
    buildAccessToken(client, TESTUSER_USERNAME, ACCESS_SCOPES);
    mvc.perform(get(REFRESH_TOKENS_BASE_PATH + "?clientId=" + TEST_CLIENT_ID))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults").value(1));

    mvc.perform(get(ACCESS_TOKENS_BASE_PATH + "?clientId=" + TEST_CLIENT_ID))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults").value(2));

    mvc
      .perform(patch(ClientManagementAPIController.ENDPOINT + "/{clientId}/revoke-refresh-tokens",
          TEST_CLIENT_ID))
      .andExpect(OK);

    mvc.perform(get(REFRESH_TOKENS_BASE_PATH + "?clientId=" + TEST_CLIENT_ID))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults").value(0));

    mvc.perform(get(ACCESS_TOKENS_BASE_PATH + "?clientId=" + TEST_CLIENT_ID))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults").value(1));
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  void testClientRevokeAllAccessTokensWorks() throws Exception {

    ClientDetailsEntity client = clientDetailsService.loadClientByClientId(TEST_CLIENT_ID);

    buildAccessToken(client, TESTUSER_USERNAME, REFRESH_SCOPES);
    buildAccessToken(client, TESTUSER_USERNAME, ACCESS_SCOPES);

    mvc.perform(get(REFRESH_TOKENS_BASE_PATH + "?clientId=" + TEST_CLIENT_ID))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults").value(1));
    mvc.perform(get(ACCESS_TOKENS_BASE_PATH + "?clientId=" + TEST_CLIENT_ID))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults").value(2));

    mvc
      .perform(patch(ClientManagementAPIController.ENDPOINT + "/{clientId}/revoke-access-tokens",
          TEST_CLIENT_ID))
      .andExpect(OK);

    mvc.perform(get(REFRESH_TOKENS_BASE_PATH + "?clientId=" + TEST_CLIENT_ID))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults").value(1));

    mvc.perform(get(ACCESS_TOKENS_BASE_PATH + "?clientId=" + TEST_CLIENT_ID))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults").value(0));
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  void testResetClient() throws Exception {

    ClientDetailsEntity client = clientDetailsService.loadClientByClientId(TEST_CLIENT_ID);

    buildAccessToken(client, TESTUSER_USERNAME, REFRESH_SCOPES);
    buildAccessToken(client, TESTUSER_USERNAME, ACCESS_SCOPES);

    mvc.perform(get(REFRESH_TOKENS_BASE_PATH + "?clientId=" + TEST_CLIENT_ID))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults").value(1));

    mvc.perform(get(ACCESS_TOKENS_BASE_PATH + "?clientId=" + TEST_CLIENT_ID))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults").value(2));

    String oldSecret = client.getClientSecret();
    String newSecret = mvc
      .perform(patch(ClientManagementAPIController.ENDPOINT + "/{clientId}/reset-client",
          TEST_CLIENT_ID))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    assertNotEquals(oldSecret, newSecret);

    mvc.perform(get(REFRESH_TOKENS_BASE_PATH + "?clientId=" + TEST_CLIENT_ID))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults").value(0));

    mvc.perform(get(ACCESS_TOKENS_BASE_PATH + "?clientId=" + TEST_CLIENT_ID))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults").value(0));

  }
}
