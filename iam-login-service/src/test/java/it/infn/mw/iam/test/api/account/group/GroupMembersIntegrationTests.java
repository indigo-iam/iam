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
package it.infn.mw.iam.test.api.account.group;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.UUID;
import java.util.function.Supplier;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import it.infn.mw.iam.core.group.IamGroupService;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAccountGroupMembership;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamGroupRepository;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@WithAnonymousUser
public class GroupMembersIntegrationTests {

  private static final String EXPECTED_USER_NOT_FOUND = "expected user not found";
  private static final String EXPECTED_GROUP_NOT_FOUND = "expected group not found";

  private static final String ADMIN_USER = "admin";
  private static final String TEST_USER = "test";
  private static final String TEST_001_GROUP = "Test-001";
  private static final String TEST_001_GROUP_ID = "c617d586-54e6-411d-8e38-649677980001";

  private static final String TEST_001_GM = "GM:" + TEST_001_GROUP_ID;

  @Autowired
  private IamAccountService accountService;

  @Autowired
  private IamGroupService groupService;

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private IamGroupRepository groupRepo;

  @Autowired
  private MockMvc mvc;

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  @Before
  public void setup() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @After
  public void cleanupOAuthUser() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  private Supplier<AssertionError> assertionError(String message) {
    return () -> new AssertionError(message);
  }

  private void addAccountToGroup(IamAccount account, IamGroup group) {
    accountService.addToGroup(account, group);
  }

  @Test
  public void addGroupMemberRequiresAuthenticatedUser() throws Exception {
    IamAccount account =
        accountRepo.findByUsername(TEST_USER).orElseThrow(assertionError(EXPECTED_USER_NOT_FOUND));

    IamGroup group =
        groupRepo.findByName(TEST_001_GROUP).orElseThrow(assertionError(EXPECTED_GROUP_NOT_FOUND));

    mvc.perform(post("/iam/account/{account}/groups/{group}", account.getUuid(), group.getUuid()))
      .andExpect(status().isUnauthorized());
  }

  @Test
  public void removeGroupMemberRequiresAuthenticatedUser() throws Exception {
    IamAccount account =
        accountRepo.findByUsername(TEST_USER).orElseThrow(assertionError(EXPECTED_USER_NOT_FOUND));

    IamGroup group =
        groupRepo.findByName(TEST_001_GROUP).orElseThrow(assertionError(EXPECTED_GROUP_NOT_FOUND));

    mvc.perform(delete("/iam/account/{account}/groups/{group}", account.getUuid(), group.getUuid()))
      .andExpect(status().isUnauthorized());

  }

  @Test
  @WithMockUser(username = TEST_USER, roles = "USER")
  public void addGroupMemberRequiresPrivileges() throws Exception {
    IamAccount account =
        accountRepo.findByUsername(TEST_USER).orElseThrow(assertionError(EXPECTED_USER_NOT_FOUND));

    IamGroup group =
        groupRepo.findByName(TEST_001_GROUP).orElseThrow(assertionError(EXPECTED_GROUP_NOT_FOUND));

    mvc.perform(post("/iam/account/{account}/groups/{group}", account.getUuid(), group.getUuid()))
      .andExpect(status().isForbidden());
  }

  @Test
  @WithMockUser(username = TEST_USER, roles = "USER")
  public void removeGroupMemberRequiresPrivileges() throws Exception {
    IamAccount account =
        accountRepo.findByUsername(TEST_USER).orElseThrow(assertionError(EXPECTED_USER_NOT_FOUND));

    IamGroup group =
        groupRepo.findByName(TEST_001_GROUP).orElseThrow(assertionError(EXPECTED_GROUP_NOT_FOUND));

    mvc.perform(delete("/iam/account/{account}/groups/{group}", account.getUuid(), group.getUuid()))
      .andExpect(status().isForbidden());

  }

  @Test
  @WithMockUser(username = ADMIN_USER, roles = {"USER", "ADMIN"})
  public void adminCanAddGroupMember() throws Exception {
    IamAccount account =
        accountRepo.findByUsername(TEST_USER).orElseThrow(assertionError(EXPECTED_USER_NOT_FOUND));

    IamGroup group =
        groupRepo.findByName("Test-001").orElseThrow(assertionError(EXPECTED_GROUP_NOT_FOUND));

    mvc.perform(post("/iam/account/{account}/groups/{group}", account.getUuid(), group.getUuid()))
      .andExpect(status().isCreated());

    account =
        accountRepo.findByUsername(TEST_USER).orElseThrow(assertionError(EXPECTED_USER_NOT_FOUND));

    assertThat(
        groupRepo.findGroupByMemberAccountUuidAndGroupUuid(account.getUuid(), group.getUuid())
          .isPresent(),
        is(true));

    IamAccountGroupMembership m =
        IamAccountGroupMembership.forAccountAndGroup(null, account, group);
    assertThat(account.getGroups().contains(m), is(true));
  }

  @Test
  @WithMockUser(username = ADMIN_USER, roles = {"USER", "ADMIN"})
  public void adminCanRemoveMember() throws Exception {
    IamAccount account =
        accountRepo.findByUsername(TEST_USER).orElseThrow(assertionError(EXPECTED_USER_NOT_FOUND));

    IamGroup group =
        groupRepo.findByName(TEST_001_GROUP).orElseThrow(assertionError(EXPECTED_GROUP_NOT_FOUND));

    addAccountToGroup(account, group);

    mvc.perform(delete("/iam/account/{account}/groups/{group}", account.getUuid(), group.getUuid()))
      .andExpect(status().isNoContent());

    group =
        groupRepo.findByName(TEST_001_GROUP).orElseThrow(assertionError(EXPECTED_GROUP_NOT_FOUND));

    assertThat(
        groupRepo.findGroupByMemberAccountUuidAndGroupUuid(account.getUuid(), group.getUuid())
          .isPresent(),
        is(false));

    IamAccountGroupMembership m =
        IamAccountGroupMembership.forAccountAndGroup(null, account, group);
    assertThat(account.getGroups().contains(m), is(false));

  }

  @Test
  @WithMockUser(username = TEST_USER, roles = {"USER", TEST_001_GM})
  public void groupManagerCanAddMember() throws Exception {
    IamAccount account =
        accountRepo.findByUsername(TEST_USER).orElseThrow(assertionError(EXPECTED_USER_NOT_FOUND));

    IamGroup group =
        groupRepo.findByName(TEST_001_GROUP).orElseThrow(assertionError(EXPECTED_GROUP_NOT_FOUND));

    mvc.perform(post("/iam/account/{account}/groups/{group}", account.getUuid(), group.getUuid()))
      .andExpect(status().isCreated());

    group =
        groupRepo.findByName(TEST_001_GROUP).orElseThrow(assertionError(EXPECTED_GROUP_NOT_FOUND));

    assertThat(
        groupRepo.findGroupByMemberAccountUuidAndGroupUuid(account.getUuid(), group.getUuid())
          .isPresent(),
        is(true));

    IamAccountGroupMembership m =
        IamAccountGroupMembership.forAccountAndGroup(null, account, group);
    assertThat(account.getGroups().contains(m), is(true));
  }


  @Test
  @WithMockUser(username = TEST_USER, roles = {"USER", TEST_001_GM})
  public void groupManagerCanRemoveMember() throws Exception {
    IamAccount account =
        accountRepo.findByUsername(TEST_USER).orElseThrow(assertionError(EXPECTED_USER_NOT_FOUND));

    IamGroup group =
        groupRepo.findByName(TEST_001_GROUP).orElseThrow(assertionError(EXPECTED_GROUP_NOT_FOUND));

    addAccountToGroup(account, group);

    mvc.perform(delete("/iam/account/{account}/groups/{group}", account.getUuid(), group.getUuid()))
      .andExpect(status().isNoContent());

    group =
        groupRepo.findByName(TEST_001_GROUP).orElseThrow(assertionError(EXPECTED_GROUP_NOT_FOUND));

    assertThat(
        groupRepo.findGroupByMemberAccountUuidAndGroupUuid(account.getUuid(), group.getUuid())
          .isPresent(),
        is(false));

    IamAccountGroupMembership m =
        IamAccountGroupMembership.forAccountAndGroup(null, account, group);
    assertThat(account.getGroups().contains(m), is(false));

  }

  @Test
  @WithMockUser(username = ADMIN_USER, roles = {"USER", "ADMIN"})
  public void cannotChangeMembershipForUnknownGroupOrAccount() throws Exception {

    IamAccount account =
        accountRepo.findByUsername(TEST_USER).orElseThrow(assertionError(EXPECTED_USER_NOT_FOUND));

    IamGroup group =
        groupRepo.findByName(TEST_001_GROUP).orElseThrow(assertionError(EXPECTED_GROUP_NOT_FOUND));

    String randomUuid = UUID.randomUUID().toString();

    mvc.perform(post("/iam/account/{account}/groups/{group}", randomUuid, group.getUuid()))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", containsString("Account not found")));

    mvc.perform(post("/iam/account/{account}/groups/{group}", account.getUuid(), randomUuid))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", containsString("Group not found")));

    mvc.perform(delete("/iam/account/{account}/groups/{group}", randomUuid, group.getUuid()))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", containsString("Account not found")));

    mvc.perform(delete("/iam/account/{account}/groups/{group}", account.getUuid(), randomUuid))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", containsString("Group not found")));

  }

  @Test
  @WithMockUser(username = ADMIN_USER, roles = {"USER", "ADMIN"})
  public void intermediateGroupMembershipIsEnforcedOnAdd() throws Exception {

    // Create group hierarchy
    IamGroup rootGroup = new IamGroup();
    rootGroup.setName("root");

    rootGroup = groupService.createGroup(rootGroup);

    IamGroup subgroup = new IamGroup();
    subgroup.setName("root/subgroup");
    subgroup.setParentGroup(rootGroup);

    subgroup = groupService.createGroup(subgroup);

    IamGroup subsubgroup = new IamGroup();
    subsubgroup.setName("root/subgroup/subsubgroup");
    subsubgroup.setParentGroup(subgroup);

    subsubgroup = groupService.createGroup(subsubgroup);

    IamGroup sibling = new IamGroup();
    sibling.setName("root/sibling");
    sibling.setParentGroup(rootGroup);
    sibling = groupService.createGroup(sibling);

    IamAccount account =
        accountRepo.findByUsername(TEST_USER).orElseThrow(assertionError(EXPECTED_USER_NOT_FOUND));

    mvc
      .perform(
          post("/iam/account/{account}/groups/{group}", account.getUuid(), subsubgroup.getUuid()))
      .andExpect(status().isCreated());

    assertThat(
        groupRepo.findGroupByMemberAccountUuidAndGroupUuid(account.getUuid(), subgroup.getUuid())
          .isPresent(),
        is(true));

    assertThat(
        groupRepo.findGroupByMemberAccountUuidAndGroupUuid(account.getUuid(), rootGroup.getUuid())
          .isPresent(),
        is(true));

    assertThat(
        groupRepo.findGroupByMemberAccountUuidAndGroupUuid(account.getUuid(), sibling.getUuid())
          .isPresent(),
        is(false));


    IamAccountGroupMembership m =
        IamAccountGroupMembership.forAccountAndGroup(null, account, subsubgroup);

    assertThat(account.getGroups().contains(m), is(true));

    m = IamAccountGroupMembership.forAccountAndGroup(null, account, subgroup);

    assertThat(account.getGroups().contains(m), is(true));

    m = IamAccountGroupMembership.forAccountAndGroup(null, account, rootGroup);

    assertThat(account.getGroups().contains(m), is(true));

  }

  @Test
  @WithMockUser(username = ADMIN_USER, roles = {"USER", "ADMIN"})
  public void intermediateGroupMembershipIsEnforcedOnRemove() throws Exception {

    // Create group hierarchy
    IamGroup rootGroup = new IamGroup();
    rootGroup.setName("root");

    rootGroup = groupService.createGroup(rootGroup);

    IamGroup subgroup = new IamGroup();
    subgroup.setName("root/subgroup");
    subgroup.setParentGroup(rootGroup);

    subgroup = groupService.createGroup(subgroup);

    IamGroup subsubgroup = new IamGroup();
    subsubgroup.setName("root/subgroup/subsubgroup");
    subsubgroup.setParentGroup(subgroup);

    subsubgroup = groupService.createGroup(subsubgroup);

    IamGroup sibling = new IamGroup();
    sibling.setName("root/sibling");
    sibling.setParentGroup(rootGroup);
    sibling = groupService.createGroup(sibling);

    IamAccount account =
        accountRepo.findByUsername(TEST_USER).orElseThrow(assertionError(EXPECTED_USER_NOT_FOUND));

    // Add test user to /root/subgroup and /root/sibling
    mvc
      .perform(post("/iam/account/{account}/groups/{group}", account.getUuid(), subgroup.getUuid()))
      .andExpect(status().isCreated());

    mvc.perform(post("/iam/account/{account}/groups/{group}", account.getUuid(), sibling.getUuid()))
      .andExpect(status().isCreated());

    assertThat(
        groupRepo.findGroupByMemberAccountUuidAndGroupUuid(account.getUuid(), subgroup.getUuid())
          .isPresent(),
        is(true));

    assertThat(
        groupRepo.findGroupByMemberAccountUuidAndGroupUuid(account.getUuid(), sibling.getUuid())
          .isPresent(),
        is(true));

    assertThat(
        groupRepo.findGroupByMemberAccountUuidAndGroupUuid(account.getUuid(), rootGroup.getUuid())
          .isPresent(),
        is(true));


    IamAccountGroupMembership m =
        IamAccountGroupMembership.forAccountAndGroup(null, account, subgroup);

    assertThat(account.getGroups().contains(m), is(true));

    m = IamAccountGroupMembership.forAccountAndGroup(null, account, rootGroup);

    assertThat(account.getGroups().contains(m), is(true));

    m = IamAccountGroupMembership.forAccountAndGroup(null, account, sibling);

    assertThat(account.getGroups().contains(m), is(true));

    // Remove test user from /root
    mvc
      .perform(
          delete("/iam/account/{account}/groups/{group}", account.getUuid(), rootGroup.getUuid()))
      .andExpect(status().isNoContent());

    assertThat(
        groupRepo.findGroupByMemberAccountUuidAndGroupUuid(account.getUuid(), rootGroup.getUuid())
          .isPresent(),
        is(false));

    assertThat(
        groupRepo.findGroupByMemberAccountUuidAndGroupUuid(account.getUuid(), subgroup.getUuid())
          .isPresent(),
        is(false));

    assertThat(
        groupRepo.findGroupByMemberAccountUuidAndGroupUuid(account.getUuid(), sibling.getUuid())
          .isPresent(),
        is(false));

    // Add test user to /root/subgroup/subsubgroup
    mvc
      .perform(
          post("/iam/account/{account}/groups/{group}", account.getUuid(), subsubgroup.getUuid()))
      .andExpect(status().isCreated());

    assertThat(
        groupRepo.findGroupByMemberAccountUuidAndGroupUuid(account.getUuid(), subgroup.getUuid())
          .isPresent(),
        is(true));

    assertThat(
        groupRepo.findGroupByMemberAccountUuidAndGroupUuid(account.getUuid(), subsubgroup.getUuid())
          .isPresent(),
        is(true));

    assertThat(
        groupRepo.findGroupByMemberAccountUuidAndGroupUuid(account.getUuid(), rootGroup.getUuid())
          .isPresent(),
        is(true));

    // Remove test user from /root/subgroup/subsubgroup
    mvc
      .perform(
          delete("/iam/account/{account}/groups/{group}", account.getUuid(), subsubgroup.getUuid()))
      .andExpect(status().isNoContent());

    assertThat(
        groupRepo.findGroupByMemberAccountUuidAndGroupUuid(account.getUuid(), subsubgroup.getUuid())
          .isPresent(),
        is(false));

    assertThat(
        groupRepo.findGroupByMemberAccountUuidAndGroupUuid(account.getUuid(), subgroup.getUuid())
          .isPresent(),
        is(true));

    assertThat(
        groupRepo.findGroupByMemberAccountUuidAndGroupUuid(account.getUuid(), rootGroup.getUuid())
          .isPresent(),
        is(true));
  }


}
