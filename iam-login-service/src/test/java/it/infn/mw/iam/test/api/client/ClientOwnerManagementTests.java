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

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.client.IamAccountClientRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.oauth.SecurityContextUtils;
import org.mitre.oauth2.model.ClientDetailsEntity;

@SpringBootTest(classes = {IamLoginService.class, CoreControllerTestSupport.class},
    webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Transactional
class ClientOwnerManagementTests {

  static final String OWNERS_RESOURCE = "/iam/api/clients/{clientId}/owners";
  static final String OWNER_RESOURCE = "/iam/api/clients/{clientId}/owners/{accountId}";

  static final String CLIENT_ID = "client";

  static final String UNKNOWN_UUID = "7b3aa1fa-6e1b-40a7-9c85-14a1cd23a1a9";

  @Autowired
  SecurityContextUtils context;

  @Autowired
  MockMvc mvc;

  @Autowired
  IamAccountRepository accountRepo;

  @Autowired
  IamClientRepository clientRepo;

  @Autowired
  IamAccountClientRepository accountClientRepo;

  @Autowired
  ClientService clientService;

  IamAccount testAccount;
  IamAccount otherAccount;
  ClientDetailsEntity client;

  @BeforeEach
  void setup() {
    context.cleanupSecurityContext();
    testAccount = findAccount("test");
    otherAccount = findAccount("test_100");
    client = clientRepo.findByClientId(CLIENT_ID)
      .orElseThrow(() -> new AssertionError("Expected client not found: " + CLIENT_ID));
    accountClientRepo.deleteByClientId(client.getId());
  }

  private IamAccount findAccount(String username) {
    return accountRepo.findByUsername(username)
      .orElseThrow(() -> new AssertionError("Expected account not found: " + username));
  }

  private void linkOwner(IamAccount account) {
    clientService.linkClientToAccount(client, account);
  }

  private boolean isOwner(IamAccount account) {
    return accountClientRepo.findByAccountAndClient(account, client).isPresent();
  }

  @Test
  @WithMockUser(username = "test", roles = {"USER"})
  void ownerCanListOwnersFromDashboardSession() throws Exception {
    linkOwner(testAccount);

    mvc.perform(get(OWNERS_RESOURCE, CLIENT_ID))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.totalResults", is(1)));
  }

  @Test
  @WithMockOAuthUser(user = "test", authorities = {"ROLE_USER"}, scopes = {"openid"})
  void ownerCanAddAndRemoveCoOwners() throws Exception {
    linkOwner(testAccount);

    mvc.perform(post(OWNER_RESOURCE, CLIENT_ID, otherAccount.getUuid()))
      .andExpect(status().isCreated());
    assertThat(isOwner(otherAccount), is(true));

    mvc.perform(delete(OWNER_RESOURCE, CLIENT_ID, otherAccount.getUuid()))
      .andExpect(status().isNoContent());
    assertThat(isOwner(otherAccount), is(false));
  }

  @Test
  @WithMockOAuthUser(user = "test", authorities = {"ROLE_USER"}, scopes = {"openid"})
  void ownerCannotRemoveTheLastOwner() throws Exception {
    linkOwner(testAccount);

    mvc.perform(delete(OWNER_RESOURCE, CLIENT_ID, testAccount.getUuid()))
      .andExpect(status().isBadRequest());
    assertThat(isOwner(testAccount), is(true));
  }

  @Test
  @WithMockOAuthUser(user = "test", authorities = {"ROLE_USER"}, scopes = {"openid"})
  void ownerCanLeaveWhenAnotherOwnerRemains() throws Exception {
    linkOwner(testAccount);
    linkOwner(otherAccount);

    mvc.perform(delete(OWNER_RESOURCE, CLIENT_ID, testAccount.getUuid()))
      .andExpect(status().isNoContent());
    assertThat(isOwner(testAccount), is(false));
    assertThat(isOwner(otherAccount), is(true));
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_USER", "ROLE_ADMIN"},
      scopes = {"iam:admin.write"})
  void adminCanRemoveTheLastOwner() throws Exception {
    linkOwner(testAccount);

    mvc.perform(delete(OWNER_RESOURCE, CLIENT_ID, testAccount.getUuid()))
      .andExpect(status().isNoContent());
    assertThat(isOwner(testAccount), is(false));
  }

  @Test
  @WithMockOAuthUser(user = "test_100", authorities = {"ROLE_USER"}, scopes = {"openid"})
  void nonOwnersCannotManageOwners() throws Exception {
    linkOwner(testAccount);

    mvc.perform(get(OWNERS_RESOURCE, CLIENT_ID)).andExpect(status().isForbidden());
    mvc.perform(post(OWNER_RESOURCE, CLIENT_ID, otherAccount.getUuid()))
      .andExpect(status().isForbidden());
    mvc.perform(delete(OWNER_RESOURCE, CLIENT_ID, testAccount.getUuid()))
      .andExpect(status().isForbidden());
  }

  @Test
  @WithMockOAuthUser(user = "test", authorities = {"ROLE_USER"}, scopes = {"openid"})
  void unknownAccountsAndClientsGiveNotFound() throws Exception {
    linkOwner(testAccount);

    mvc.perform(post(OWNER_RESOURCE, CLIENT_ID, UNKNOWN_UUID))
      .andExpect(status().isNotFound());
    mvc.perform(delete(OWNER_RESOURCE, CLIENT_ID, UNKNOWN_UUID))
      .andExpect(status().isNotFound());
  }

  @Test
  @WithMockOAuthUser(user = "admin", authorities = {"ROLE_USER", "ROLE_ADMIN"},
      scopes = {"iam:admin.write"})
  void unknownAccountGivesNotFoundToAdminsToo() throws Exception {
    mvc.perform(post(OWNER_RESOURCE, CLIENT_ID, UNKNOWN_UUID))
      .andExpect(status().isNotFound());
  }

  @Test
  @WithMockOAuthUser(user = "test", authorities = {"ROLE_USER"}, scopes = {"openid"})
  void addingAnExistingOwnerIsHarmless() throws Exception {
    linkOwner(testAccount);
    linkOwner(otherAccount);

    mvc.perform(post(OWNER_RESOURCE, CLIENT_ID, otherAccount.getUuid()))
      .andExpect(status().isCreated());

    mvc.perform(get(OWNERS_RESOURCE, CLIENT_ID))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.totalResults", is(2)));
  }

  @Test
  @WithMockOAuthUser(user = "test", authorities = {"ROLE_USER"}, scopes = {"openid"})
  void ownerCanAddCoOwnerByUsername() throws Exception {
    linkOwner(testAccount);

    mvc.perform(post(OWNERS_RESOURCE, CLIENT_ID).param("username", "test_100"))
      .andExpect(status().isCreated());
    assertThat(isOwner(otherAccount), is(true));
  }

  @Test
  @WithMockOAuthUser(user = "test", authorities = {"ROLE_USER"}, scopes = {"openid"})
  void unknownUsernameGivesNotFound() throws Exception {
    linkOwner(testAccount);

    mvc.perform(post(OWNERS_RESOURCE, CLIENT_ID).param("username", "no_such_user"))
      .andExpect(status().isNotFound());
  }

  @Test
  @WithMockOAuthUser(user = "test_100", authorities = {"ROLE_USER"}, scopes = {"openid"})
  void nonOwnersCannotAddByUsername() throws Exception {
    linkOwner(testAccount);

    mvc.perform(post(OWNERS_RESOURCE, CLIENT_ID).param("username", "test_100"))
      .andExpect(status().isForbidden());
  }

  @Test
  @WithMockOAuthUser(user = "test", authorities = {"ROLE_USER"}, scopes = {"openid"})
  void ownershipGrantsNoOtherManagementOperation() throws Exception {
    linkOwner(testAccount);

    mvc.perform(get("/iam/api/clients/{clientId}", CLIENT_ID))
      .andExpect(status().isForbidden());
    mvc.perform(post("/iam/api/clients/{clientId}/rat", CLIENT_ID))
      .andExpect(status().isForbidden());
    mvc.perform(delete("/iam/api/clients/{clientId}", CLIENT_ID))
      .andExpect(status().isForbidden());
  }

}
