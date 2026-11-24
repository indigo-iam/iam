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
package it.infn.mw.iam.test.api.account.management;

import static it.infn.mw.iam.core.IamRegistrationRequestStatus.APPROVED;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAuthority;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAuthoritiesRepository;
import it.infn.mw.iam.registration.PersistentUUIDTokenGenerator;
import it.infn.mw.iam.registration.RegistrationRequestDto;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@IamMockMvcIntegrationTest
class UserManagerTests {

  static final String ROLE_USER_MANAGER = "ROLE_USER_MANAGER";

  static final String MANAGER = "test_100";
  static final String OTHER_MANAGER = "test_101";
  static final String USER = "test_102";
  static final String SERVICE_ACCOUNT = "test_103";
  static final String ADMIN = "admin";

  static final String UNKNOWN_UUID = "7b3aa1fa-6e1b-40a7-9c85-14a1cd23a1a9";

  static final String AUTHORITIES = "/iam/account/{id}/authorities";

  @Autowired
  MockMvc mvc;

  @Autowired
  MockOAuth2Filter mockOAuth2Filter;

  @Autowired
  IamAccountRepository accountRepo;

  @Autowired
  IamAuthoritiesRepository authoritiesRepo;

  @Autowired
  PersistentUUIDTokenGenerator generator;

  @Autowired
  ObjectMapper mapper;

  @BeforeEach
  void setup() {
    mockOAuth2Filter.cleanupSecurityContext();
    setUserManager(MANAGER, true);
    setUserManager(OTHER_MANAGER, true);

    IamAccount serviceAccount = account(SERVICE_ACCOUNT);
    serviceAccount.setServiceAccount(true);
    accountRepo.save(serviceAccount);
  }

  @AfterEach
  void teardown() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  private IamAccount account(String username) {
    return accountRepo.findByUsername(username).orElseThrow();
  }

  private String uuid(String username) {
    return account(username).getUuid();
  }

  private void setUserManager(String username, boolean userManager) {
    IamAuthority role = authoritiesRepo.findByAuthority(ROLE_USER_MANAGER).orElseThrow();
    IamAccount account = account(username);
    if (userManager) {
      account.getAuthorities().add(role);
    } else {
      account.getAuthorities().remove(role);
    }
    accountRepo.save(account);
  }

  private boolean isActive(String username) {
    return account(username).isActive();
  }

  private boolean exists(String username) {
    return accountRepo.findByUsername(username).isPresent();
  }

  private ResultActions disable(String uuid) throws Exception {
    return mvc.perform(patch("/iam/account/{id}/disable", uuid).with(csrf().asHeader()));
  }

  private ResultActions enable(String uuid) throws Exception {
    return mvc.perform(patch("/iam/account/{id}/enable", uuid).with(csrf().asHeader()));
  }

  private ResultActions remove(String uuid) throws Exception {
    return mvc.perform(delete("/scim/Users/{id}", uuid).with(csrf().asHeader()));
  }

  private ResultActions approve(String requestUuid) throws Exception {
    return mvc.perform(post("/registration/approve/{uuid}", requestUuid).with(csrf().asHeader()));
  }

  private ResultActions reject(String requestUuid) throws Exception {
    return mvc.perform(post("/registration/reject/{uuid}", requestUuid).with(csrf().asHeader()));
  }

  private RegistrationRequestDto registerAndConfirm(String username) throws Exception {

    RegistrationRequestDto request = new RegistrationRequestDto();
    request.setGivenname("Test");
    request.setFamilyname("User");
    request.setEmail(username + "@example.org");
    request.setUsername(username);
    request.setNotes("Some short notes...");

    String response = mvc
      .perform(post("/registration/create").with(csrf().asHeader())
        .contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(request)))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    mvc
      .perform(post("/registration/verify").with(csrf().asHeader())
        .contentType(APPLICATION_FORM_URLENCODED)
        .param("token", generator.getLastToken()))
      .andExpect(status().isOk());

    return mapper.readValue(response, RegistrationRequestDto.class);
  }

  @Test
  @WithMockUser(username = MANAGER, roles = {"USER", "USER_MANAGER"})
  void userManagerReadsAccounts() throws Exception {

    String user = uuid(USER);

    mvc.perform(get("/scim/Users").param("count", "1")).andExpect(status().isOk());
    mvc.perform(get("/scim/Users/{id}", user)).andExpect(status().isOk());
    mvc.perform(get("/iam/account/search").param("count", "1")).andExpect(status().isOk());
    mvc.perform(get("/iam/account/{id}/attributes", user)).andExpect(status().isOk());
    mvc.perform(get("/iam/account/{id}/labels", user)).andExpect(status().isOk());
    mvc.perform(get("/iam/account/{id}/lockout", user)).andExpect(status().isOk());
    mvc.perform(get("/iam/account/lockout/suspended")).andExpect(status().isOk());
    mvc.perform(get("/iam/account/reserved"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$", hasItems(uuid(ADMIN), uuid(MANAGER), uuid(OTHER_MANAGER),
          uuid(SERVICE_ACCOUNT))))
      .andExpect(jsonPath("$", not(hasItem(user))));
    mvc.perform(get(AUTHORITIES, uuid(OTHER_MANAGER)))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.authorities", hasItem(ROLE_USER_MANAGER)));
  }

  @Test
  @WithMockUser(username = MANAGER, roles = {"USER", "USER_MANAGER"})
  void userManagerDisablesRestoresAndRemovesUsers() throws Exception {

    String user = uuid(USER);

    disable(user).andExpect(status().isOk());
    disable(user).andExpect(status().isOk());
    assertThat(isActive(USER), is(false));

    enable(user).andExpect(status().isOk());
    assertThat(isActive(USER), is(true));

    remove(user).andExpect(status().isNoContent());
    assertThat(exists(USER), is(false));

    disable(UNKNOWN_UUID).andExpect(status().isNotFound());
    enable(UNKNOWN_UUID).andExpect(status().isNotFound());
    remove(UNKNOWN_UUID).andExpect(status().isNotFound());
  }

  @Test
  @WithMockUser(username = MANAGER, roles = {"USER", "USER_MANAGER"})
  void userManagerCannotManageAdministratorsUserManagersServiceAccountsOrItself()
      throws Exception {

    for (String username : new String[] {ADMIN, OTHER_MANAGER, SERVICE_ACCOUNT, MANAGER}) {
      disable(uuid(username)).andExpect(status().isForbidden());
      enable(uuid(username)).andExpect(status().isForbidden());
      remove(uuid(username)).andExpect(status().isForbidden());
      assertThat(isActive(username), is(true));
    }
  }

  @Test
  @WithMockUser(username = MANAGER, roles = {"USER", "USER_MANAGER"})
  void userManagerGetsNoOtherAdministratorPrivilege() throws Exception {

    mvc
      .perform(post(AUTHORITIES, uuid(MANAGER)).with(csrf().asHeader())
        .param("authority", "ROLE_ADMIN")
        .contentType(APPLICATION_FORM_URLENCODED))
      .andExpect(status().isForbidden());
    mvc
      .perform(delete(AUTHORITIES, uuid(OTHER_MANAGER)).with(csrf().asHeader())
        .param("authority", ROLE_USER_MANAGER))
      .andExpect(status().isForbidden());
    mvc.perform(delete("/iam/account/{id}/lockout", uuid(USER)).with(csrf().asHeader()))
      .andExpect(status().isForbidden());
    mvc.perform(get("/scim/Groups")).andExpect(status().isForbidden());
    mvc.perform(get("/iam/api/clients")).andExpect(status().isForbidden());
  }

  @Test
  @WithMockUser(username = MANAGER, roles = {"USER", "USER_MANAGER"})
  void userManagerApprovesAndRejectsRegistrationRequests() throws Exception {

    RegistrationRequestDto approved = registerAndConfirm("um_approved");
    RegistrationRequestDto rejected = registerAndConfirm("um_rejected");

    mvc.perform(get("/registration/list/pending"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$[*].username", hasItem("um_approved")));

    approve(approved.getUuid()).andExpect(status().isOk())
      .andExpect(jsonPath("$.status", equalTo(APPROVED.name())));
    assertThat(isActive("um_approved"), is(true));
    approve(approved.getUuid()).andExpect(status().isBadRequest());

    reject(rejected.getUuid()).andExpect(status().isOk());
    assertThat(exists("um_rejected"), is(false));
    reject(rejected.getUuid()).andExpect(status().isNotFound());
  }

  @Test
  @WithMockUser(username = MANAGER, roles = {"USER", "USER_MANAGER"})
  void sessionOfAUserThatLostTheRoleOrWasDisabledCannotChangeAnything() throws Exception {

    setUserManager(MANAGER, false);

    disable(uuid(USER)).andExpect(status().isForbidden());
    remove(uuid(USER)).andExpect(status().isForbidden());
    approve(UNKNOWN_UUID).andExpect(status().isForbidden());
    reject(UNKNOWN_UUID).andExpect(status().isForbidden());

    setUserManager(MANAGER, true);
    IamAccount manager = account(MANAGER);
    manager.setActive(false);
    accountRepo.save(manager);

    disable(uuid(USER)).andExpect(status().isForbidden());
    assertThat(isActive(USER), is(true));
  }

  @Test
  @WithMockOAuthUser(user = MANAGER, authorities = {"ROLE_USER", ROLE_USER_MANAGER},
      scopes = {"openid", "iam:user.read", "iam:user.write"})
  void userManagementScopesGiveTokensWhatTheRoleGivesSessions() throws Exception {

    mvc.perform(get("/scim/Users").param("count", "1")).andExpect(status().isOk());
    mvc.perform(get("/registration/list/pending")).andExpect(status().isOk());
    mvc.perform(get("/scim/Groups")).andExpect(status().isForbidden());

    disable(uuid(ADMIN)).andExpect(status().isForbidden());
    disable(uuid(USER)).andExpect(status().isOk());
    enable(uuid(USER)).andExpect(status().isOk());
    remove(uuid(USER)).andExpect(status().isNoContent());
    assertThat(exists(USER), is(false));
  }

  @Test
  @WithMockOAuthUser(user = MANAGER, authorities = {"ROLE_USER", ROLE_USER_MANAGER},
      scopes = {"openid", "iam:user.read"})
  void readScopeDoesNotAllowChanges() throws Exception {

    mvc.perform(get("/scim/Users").param("count", "1")).andExpect(status().isOk());
    disable(uuid(USER)).andExpect(status().isForbidden());
    remove(uuid(USER)).andExpect(status().isForbidden());
    approve(UNKNOWN_UUID).andExpect(status().isForbidden());
    assertThat(isActive(USER), is(true));
  }

  @Test
  @WithMockUser(username = "test", roles = {"USER"})
  void regularUsersAreRefused() throws Exception {

    mvc.perform(get("/scim/Users")).andExpect(status().isForbidden());
    mvc.perform(get("/iam/account/reserved")).andExpect(status().isForbidden());
    mvc.perform(get("/registration/list/pending")).andExpect(status().isForbidden());
    disable(uuid(USER)).andExpect(status().isForbidden());
    enable(uuid(USER)).andExpect(status().isForbidden());
    remove(uuid(USER)).andExpect(status().isForbidden());
    approve(UNKNOWN_UUID).andExpect(status().isForbidden());
  }

  @Test
  @WithMockUser(username = ADMIN, roles = {"USER", "ADMIN"})
  void administratorsGrantTheRoleAndManageEveryAccount() throws Exception {

    mvc
      .perform(post(AUTHORITIES, uuid(USER)).with(csrf().asHeader())
        .param("authority", ROLE_USER_MANAGER)
        .contentType(APPLICATION_FORM_URLENCODED))
      .andExpect(status().isOk());
    mvc.perform(get(AUTHORITIES, uuid(USER)))
      .andExpect(jsonPath("$.authorities", hasItem(ROLE_USER_MANAGER)));
    mvc
      .perform(delete(AUTHORITIES, uuid(USER)).with(csrf().asHeader())
        .param("authority", ROLE_USER_MANAGER))
      .andExpect(status().isOk());

    disable(uuid(MANAGER)).andExpect(status().isOk());
    assertThat(isActive(MANAGER), is(false));
    disable(uuid(SERVICE_ACCOUNT)).andExpect(status().isOk());
    remove(uuid(OTHER_MANAGER)).andExpect(status().isNoContent());
    assertThat(exists(OTHER_MANAGER), is(false));
  }
}
