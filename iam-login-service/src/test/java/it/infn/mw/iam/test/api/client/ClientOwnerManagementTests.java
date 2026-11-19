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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.is;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.DashboardProperties;
import it.infn.mw.iam.config.client_registration.ClientRegistrationProperties;
import it.infn.mw.iam.config.client_registration.ClientRegistrationProperties.ClientRegistrationAuthorizationPolicy;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.client.IamAccountClientRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@IamMockMvcIntegrationTest
class ClientOwnerManagementTests {

  static final String OWNERS = "/iam/api/clients/{clientId}/owners";
  static final String OWNER = "/iam/api/clients/{clientId}/owners/{accountId}";

  static final String CLIENT_ID = "client";
  static final String OWNER_USER = "test";
  static final String OTHER_USER = "test_100";

  static final String UNKNOWN_UUID = "7b3aa1fa-6e1b-40a7-9c85-14a1cd23a1a9";

  @Autowired
  MockMvc mvc;

  @Autowired
  MockOAuth2Filter mockOAuth2Filter;

  @Autowired
  IamAccountRepository accountRepo;

  @Autowired
  IamClientRepository clientRepo;

  @Autowired
  IamAccountClientRepository accountClientRepo;

  @Autowired
  ClientService clientService;

  @Autowired
  IamProperties iamProperties;

  @Autowired
  ClientRegistrationProperties registrationProperties;

  @BeforeEach
  void setup() {
    mockOAuth2Filter.cleanupSecurityContext();
    ClientDetailsEntity client = clientRepo.findByClientId(CLIENT_ID).orElseThrow();
    accountClientRepo.deleteByClientId(client.getId());
    clientService.linkClientToAccount(client, accountRepo.findByUsername(OWNER_USER).orElseThrow());
  }

  @AfterEach
  void teardown() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  private String uuid(String username) {
    return accountRepo.findByUsername(username).orElseThrow().getUuid();
  }

  private List<String> owners() {
    return accountClientRepo.findByClientClientId(CLIENT_ID, Pageable.unpaged())
      .map(o -> o.getAccount().getUsername())
      .getContent();
  }

  private ResultActions add(String accountUuid) throws Exception {
    return mvc.perform(post(OWNER, CLIENT_ID, accountUuid).with(csrf().asHeader()));
  }

  private ResultActions addByUsername(String username) throws Exception {
    return mvc.perform(post(OWNERS, CLIENT_ID).with(csrf().asHeader()).param("username", username));
  }

  private ResultActions remove(String accountUuid) throws Exception {
    return mvc.perform(delete(OWNER, CLIENT_ID, accountUuid).with(csrf().asHeader()));
  }

  @Test
  @WithMockUser(username = OWNER_USER, roles = {"USER"})
  void ownerAddsAndRemovesOwners() throws Exception {

    add(uuid(OTHER_USER)).andExpect(status().isCreated());
    add(uuid(OTHER_USER)).andExpect(status().isCreated());
    addByUsername("test_101").andExpect(status().isCreated());
    assertThat(owners(), containsInAnyOrder(OWNER_USER, OTHER_USER, "test_101"));

    remove(uuid("test_101")).andExpect(status().isNoContent());
    remove(uuid("test_101")).andExpect(status().isNoContent());
    remove(uuid(OWNER_USER)).andExpect(status().isNoContent());
    assertThat(owners(), containsInAnyOrder(OTHER_USER));

    add(uuid(OWNER_USER)).andExpect(status().isForbidden());
    mvc.perform(get(OWNERS, CLIENT_ID)).andExpect(status().isForbidden());
  }

  private ResultActions removeAs(String caller, String accountUuid) throws Exception {
    return mvc.perform(delete(OWNER, CLIENT_ID, accountUuid).with(user(caller).roles("USER"))
      .with(csrf().asHeader()));
  }

  @Test
  @WithMockUser(username = OWNER_USER, roles = {"USER"})
  void ownersAreListedBySeniorityAndRemoveOnlyTheOwnersAddedAfterThem() throws Exception {

    add(uuid(OTHER_USER)).andExpect(status().isCreated());
    add(uuid("test_101")).andExpect(status().isCreated());

    mvc.perform(get(OWNERS, CLIENT_ID))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.totalResults", is(3)))
      .andExpect(jsonPath("$.Resources[*].userName", contains(OWNER_USER, OTHER_USER, "test_101")))
      .andExpect(jsonPath("$.Resources[0].id").exists())
      .andExpect(jsonPath("$.Resources[0].name.formatted").exists())
      .andExpect(jsonPath("$.Resources[*].emails").doesNotExist());

    removeAs("test_101", uuid(OTHER_USER)).andExpect(status().isForbidden());
    removeAs(OTHER_USER, uuid(OWNER_USER)).andExpect(status().isForbidden());
    assertThat(owners(), containsInAnyOrder(OWNER_USER, OTHER_USER, "test_101"));

    removeAs(OTHER_USER, uuid("test_101")).andExpect(status().isNoContent());
    removeAs(OTHER_USER, uuid(OTHER_USER)).andExpect(status().isNoContent());
    assertThat(owners(), containsInAnyOrder(OWNER_USER));
  }

  @Test
  @WithMockUser(username = OWNER_USER, roles = {"USER"})
  void theLastOwnerCannotBeRemovedAndBadRequestsAreRefused() throws Exception {

    remove(uuid(OWNER_USER)).andExpect(status().isBadRequest());
    assertThat(owners(), containsInAnyOrder(OWNER_USER));

    add(UNKNOWN_UUID).andExpect(status().isNotFound());
    remove(UNKNOWN_UUID).andExpect(status().isNotFound());
    addByUsername("no_such_user").andExpect(status().isNotFound());
    addByUsername(" ").andExpect(status().isBadRequest());
    mvc.perform(post(OWNERS, CLIENT_ID).with(csrf().asHeader()))
      .andExpect(status().isBadRequest());
  }

  @Test
  @WithMockUser(username = OTHER_USER, roles = {"USER"})
  void usersThatDoNotOwnTheClientAreRefused() throws Exception {

    mvc.perform(get(OWNERS, CLIENT_ID)).andExpect(status().isForbidden());
    add(uuid(OTHER_USER)).andExpect(status().isForbidden());
    addByUsername(OTHER_USER).andExpect(status().isForbidden());
    remove(uuid(OWNER_USER)).andExpect(status().isForbidden());
    assertThat(owners(), containsInAnyOrder(OWNER_USER));
  }

  @Test
  @WithMockOAuthUser(user = OWNER_USER, authorities = {"ROLE_USER"},
      scopes = {"openid", "profile"})
  void accessTokensOfAnOwnerAreRefused() throws Exception {

    mvc.perform(get(OWNERS, CLIENT_ID)).andExpect(status().isForbidden());
    addByUsername(OTHER_USER).andExpect(status().isForbidden());
    remove(uuid(OWNER_USER)).andExpect(status().isForbidden());
  }

  @Test
  @WithMockOAuthUser(clientId = "iam-dashboard", user = OWNER_USER, authorities = {"ROLE_USER"},
      scopes = {"openid", "profile"})
  void tokensIssuedToTheDashboardAreAccepted() throws Exception {

    DashboardProperties dashboard = iamProperties.getDashboard();
    String clientId = dashboard.getClientId();
    boolean enabled = dashboard.isEnabled();
    dashboard.setClientId("iam-dashboard");
    dashboard.setEnabled(true);

    try {
      mvc.perform(get(OWNERS, CLIENT_ID))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.Resources[*].emails").doesNotExist());
      addByUsername(OTHER_USER).andExpect(status().isCreated());
      remove(uuid(OTHER_USER)).andExpect(status().isNoContent());
      mvc.perform(get("/iam/api/clients/{id}", CLIENT_ID)).andExpect(status().isForbidden());

      dashboard.setEnabled(false);
      mvc.perform(get(OWNERS, CLIENT_ID)).andExpect(status().isForbidden());
      addByUsername(OTHER_USER).andExpect(status().isForbidden());
    } finally {
      dashboard.setClientId(clientId);
      dashboard.setEnabled(enabled);
    }
    assertThat(owners(), containsInAnyOrder(OWNER_USER));
  }

  @Test
  @WithMockUser(username = OWNER_USER, roles = {"USER"})
  void ownersManageNothingWhereOnlyAdministratorsRegisterClients() throws Exception {

    ClientRegistrationAuthorizationPolicy allowFor = registrationProperties.getAllowFor();
    registrationProperties.setAllowFor(ClientRegistrationAuthorizationPolicy.ADMINISTRATORS);

    try {
      mvc.perform(get(OWNERS, CLIENT_ID)).andExpect(status().isForbidden());
      add(uuid(OTHER_USER)).andExpect(status().isForbidden());
      addByUsername(OTHER_USER).andExpect(status().isForbidden());
      remove(uuid(OWNER_USER)).andExpect(status().isForbidden());
    } finally {
      registrationProperties.setAllowFor(allowFor);
    }
    assertThat(owners(), containsInAnyOrder(OWNER_USER));
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_USER", "ROLE_ADMIN"},
      scopes = {"iam:admin.read", "iam:admin.write"})
  void administratorsSeeTheAccountsAndCanRemoveTheLastOwner() throws Exception {

    mvc.perform(get(OWNERS, CLIENT_ID))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.Resources[0].emails").exists());

    add(UNKNOWN_UUID).andExpect(status().isNotFound());
    mvc.perform(post(OWNER, "no-such-client", uuid(OTHER_USER)).with(csrf().asHeader()))
      .andExpect(status().isNotFound());

    remove(uuid(OWNER_USER)).andExpect(status().isNoContent());
    assertThat(owners().isEmpty(), is(true));
  }
}
