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
package it.infn.mw.iam.test.api.account.group_manager;

import static java.lang.String.format;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.UUID;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.google.common.collect.Lists;

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAuthority;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAuthoritiesRepository;
import it.infn.mw.iam.persistence.repository.IamGroupRepository;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@WithAnonymousUser
public class GroupManagerIntegrationTests {

  private static final String TEST_001_GROUP_ID = "c617d586-54e6-411d-8e38-649677980001";

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private IamGroupRepository groupRepo;

  @Autowired
  private IamAuthoritiesRepository authoritiesRepo;

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

  @Test
  public void getAccountManagerInformationRequiresAuthenticatdUser() throws Exception {
    IamAccount testUser = accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test user not found"));

    mvc.perform(get("/iam/account/{uuid}/managed-groups", testUser.getUuid()))
      .andExpect(status().isUnauthorized());

  }

  @Test
  @WithMockUser(username = "test_001", roles = {"USER"})
  public void getAccountManagerInformationRequiresAdminUser() throws Exception {
    IamAccount testUser = accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test user not found"));

    mvc.perform(get("/iam/account/{uuid}/managed-groups", testUser.getUuid()))
      .andExpect(status().isForbidden());

  }

  @Test
  @WithMockUser(username = "admin", roles = {"USER", "ADMIN"})
  public void getAccountManagerInformationWorksForAdminUser() throws Exception {
    IamAccount testUser = accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test user not found"));

    List<IamGroup> allGroups = Lists.newArrayList(groupRepo.findAll());

    mvc.perform(get("/iam/account/{uuid}/managed-groups", testUser.getUuid()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.id", equalTo(testUser.getUuid())))
      .andExpect(jsonPath("$.username", equalTo(testUser.getUsername())))
      .andExpect(jsonPath("$.managedGroups").isEmpty())
      .andExpect(jsonPath("$.unmanagedGroups").isNotEmpty())
      .andExpect(jsonPath("$.unmanagedGroups").value(hasSize(allGroups.size())));

  }

  @Test
  @WithMockUser(username = "test", roles = {"USER"})
  public void getAccountManagerInformationWorksForSameUser() throws Exception {
    IamAccount testUser = accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test user not found"));

    IamAccount adminUser = accountRepo.findByUsername("admin")
      .orElseThrow(() -> new AssertionError("Expected admin user not found"));

    List<IamGroup> allGroups = Lists.newArrayList(groupRepo.findAll());

    mvc.perform(get("/iam/account/{uuid}/managed-groups", testUser.getUuid()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.id", equalTo(testUser.getUuid())))
      .andExpect(jsonPath("$.username", equalTo(testUser.getUsername())))
      .andExpect(jsonPath("$.managedGroups").isEmpty())
      .andExpect(jsonPath("$.unmanagedGroups").isNotEmpty())
      .andExpect(jsonPath("$.unmanagedGroups").value(hasSize(allGroups.size())));


    mvc.perform(get("/iam/account/{uuid}/managed-groups", adminUser.getUuid()))
      .andExpect(status().isForbidden());

  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN"})
  public void getAccountManagerInformatReturnsBadRequestWhenAccountNotFound() throws Exception {

    String randomUuid = UUID.randomUUID().toString();

    mvc.perform(get("/iam/account/{uuid}/managed-groups", randomUuid))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", equalTo(format("Account not found for id '%s'", randomUuid))));
  }

  @Test
  @WithMockUser(username = "test", roles = {"USER"})
  public void getAccountManagerInformationReturnsRightInformatio() throws Exception {
    IamAccount testUser = accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test user not found"));

    IamAuthority auth = authoritiesRepo.findByAuthority("ROLE_GM:" + TEST_001_GROUP_ID)
      .orElseThrow(() -> new AssertionError("Expected group manager authority not found"));

    testUser.getAuthorities().add(auth);

    accountRepo.save(testUser);

    List<IamGroup> allGroups = Lists.newArrayList(groupRepo.findAll());

    mvc.perform(get("/iam/account/{uuid}/managed-groups", testUser.getUuid()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.id", equalTo(testUser.getUuid())))
      .andExpect(jsonPath("$.username", equalTo(testUser.getUsername())))
      .andExpect(jsonPath("$.managedGroups").isNotEmpty())
      .andExpect(jsonPath("$.managedGroups[0].id").value(TEST_001_GROUP_ID))
      .andExpect(jsonPath("$.unmanagedGroups").isNotEmpty())
      .andExpect(jsonPath("$.unmanagedGroups").value(hasSize(allGroups.size() - 1)));
  }

  @Test
  public void addGroupManagerRequiresAuthenticatedUser() throws Exception {
    IamAccount testUser = accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test user not found"));

    mvc
      .perform(post("/iam/account/{uuid}/managed-groups/{groupUuid}", testUser.getUuid(),
          TEST_001_GROUP_ID))
      .andExpect(MockMvcResultMatchers.status().isUnauthorized());
  }

  @Test
  @WithMockUser(username = "test", roles = {"USER"})
  public void addGroupManagerRequiresAdminUser() throws Exception {
    IamAccount testUser = accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test user not found"));

    mvc
      .perform(post("/iam/account/{uuid}/managed-groups/{groupUuid}", testUser.getUuid(),
          TEST_001_GROUP_ID))
      .andExpect(MockMvcResultMatchers.status().isForbidden());
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void addGroupManagerWorksForAdminUser() throws Exception {
    IamAccount testUser = accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test user not found"));

    mvc
      .perform(post("/iam/account/{uuid}/managed-groups/{groupUuid}", testUser.getUuid(),
          TEST_001_GROUP_ID))
      .andExpect(status().isCreated());

    List<IamGroup> allGroups = Lists.newArrayList(groupRepo.findAll());

    mvc.perform(get("/iam/account/{uuid}/managed-groups", testUser.getUuid()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.id", equalTo(testUser.getUuid())))
      .andExpect(jsonPath("$.username", equalTo(testUser.getUsername())))
      .andExpect(jsonPath("$.managedGroups").isNotEmpty())
      .andExpect(jsonPath("$.managedGroups[0].id").value(TEST_001_GROUP_ID))
      .andExpect(jsonPath("$.unmanagedGroups").isNotEmpty())
      .andExpect(jsonPath("$.unmanagedGroups").value(hasSize(allGroups.size() - 1)));
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void addGroupManagerRequiresValidUserAndGroupIds() throws Exception {
    String randomUuid = UUID.randomUUID().toString();
    IamAccount testUser = accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test user not found"));

    mvc
      .perform(
          post("/iam/account/{uuid}/managed-groups/{groupUuid}", randomUuid, TEST_001_GROUP_ID))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", equalTo(format("Account not found for id '%s'", randomUuid))));

    mvc
      .perform(
          post("/iam/account/{uuid}/managed-groups/{groupUuid}", testUser.getUuid(), randomUuid))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", equalTo(format("Group '%s' not found", randomUuid))));

  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  public void removeGroupManagerWorksForAdminUser() throws Exception {
    IamAccount testUser = accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test user not found"));


    IamAuthority auth = authoritiesRepo.findByAuthority("ROLE_GM:" + TEST_001_GROUP_ID)
      .orElseThrow(() -> new AssertionError("Expected group manager authority not found"));

    testUser.getAuthorities().add(auth);

    accountRepo.save(testUser);

    mvc
      .perform(delete("/iam/account/{uuid}/managed-groups/{groupUuid}", testUser.getUuid(),
          TEST_001_GROUP_ID))
      .andExpect(status().isNoContent());

    List<IamGroup> allGroups = Lists.newArrayList(groupRepo.findAll());

    mvc.perform(get("/iam/account/{uuid}/managed-groups", testUser.getUuid()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.id", equalTo(testUser.getUuid())))
      .andExpect(jsonPath("$.username", equalTo(testUser.getUsername())))
      .andExpect(jsonPath("$.managedGroups").isEmpty())
      .andExpect(jsonPath("$.unmanagedGroups").isNotEmpty())
      .andExpect(jsonPath("$.unmanagedGroups").value(hasSize(allGroups.size())));
  }

  @Test
  public void listGroupManagersRequiresAuthenticatedUser() throws Exception {
    mvc.perform(get("/iam/group/{uuid}/group-managers", TEST_001_GROUP_ID))
      .andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockUser(username = "test", roles = {"USER"})
  public void listGroupManagersRequiresAdminUserOrGroupManager() throws Exception {
    mvc.perform(get("/iam/group/{uuid}/group-managers", TEST_001_GROUP_ID))
      .andExpect(status().isForbidden());
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN"})
  public void listGroupManagersRequiresAdminUser() throws Exception {
    mvc.perform(get("/iam/group/{uuid}/group-managers", TEST_001_GROUP_ID))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$").isArray())
      .andExpect(jsonPath("$").isEmpty());

    IamAccount testUser = accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test user not found"));


    IamAuthority auth = authoritiesRepo.findByAuthority("ROLE_GM:" + TEST_001_GROUP_ID)
      .orElseThrow(() -> new AssertionError("Expected group manager authority not found"));

    testUser.getAuthorities().add(auth);

    accountRepo.save(testUser);

    mvc.perform(get("/iam/group/{uuid}/group-managers", TEST_001_GROUP_ID))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$").isNotEmpty())
      .andExpect(jsonPath("$", hasSize(1)))
      .andExpect(jsonPath("$[0].userName", equalTo("test")));
  }


}
