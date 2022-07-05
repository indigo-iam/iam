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
package it.infn.mw.iam.test.api.requests;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.UUID;
import java.util.function.Supplier;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.requests.model.GroupRequestDto;
import it.infn.mw.iam.api.requests.service.GroupRequestsService;
import it.infn.mw.iam.core.IamGroupRequestStatus;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.model.IamGroupRequest;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamGroupRepository;
import it.infn.mw.iam.persistence.repository.IamGroupRequestRepository;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
public class GroupRequestsDeleteTests extends GroupRequestsTestUtils {

  private final static String DELETE_URL = "/iam/group_requests/{uuid}";
  private final static String CREATE_URL = "/iam/group_requests";
  private static final String EXPECTED_USER_NOT_FOUND = "expected user not found";
  private static final String EXPECTED_GROUP_NOT_FOUND = "expected group not found";

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private IamGroupRepository groupRepo;

  @Autowired
  private IamGroupRequestRepository groupRequestRepo;

  @Autowired
  private IamAccountService accountService;

  @Autowired
  private GroupRequestsService groupRequestsService;

  @Autowired
  private MockMvc mvc;

  private Supplier<AssertionError> assertionError(String message) {
    return () -> new AssertionError(message);
  }

  private void addAccountToGroup(IamAccount account, IamGroup group) {
    accountService.addToGroup(account, group);
    for (IamGroupRequest r : group.getGroupRequests()) {
      if (account.getUuid().equals(r.getAccount().getUuid())) {
        groupRequestsService.deleteGroupRequest(r.getUuid());
      }
    }
  }

  @Test
  @WithMockUser(roles = {"ADMIN"})
  public void deletePendingGroupRequestAsAdmin() throws Exception {

    GroupRequestDto request = savePendingGroupRequest(TEST_100_USERNAME, TEST_001_GROUPNAME);

    // @formatter:off
    mvc.perform(delete(DELETE_URL, request.getUuid()))
      .andExpect(status().isNoContent());
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = {"ADMIN"})
  public void deleteApprovedGroupRequestAsAdmin() throws Exception {
    GroupRequestDto request = saveApprovedGroupRequest(TEST_100_USERNAME, TEST_001_GROUPNAME);
    // @formatter:off
    mvc.perform(delete(DELETE_URL, request.getUuid()))
      .andExpect(status().isNoContent());
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = {"USER"}, username = TEST_100_USERNAME)
  public void deletePendingGroupRequestAsUser() throws Exception {

    GroupRequestDto request = savePendingGroupRequest(TEST_100_USERNAME, TEST_001_GROUPNAME);

    // @formatter:off
    mvc.perform(delete(DELETE_URL, request.getUuid()))
      .andExpect(status().isNoContent());
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = {"USER"}, username = TEST_100_USERNAME)
  public void deleteApprovedGroupRequestAsUser() throws Exception {
    GroupRequestDto request = saveApprovedGroupRequest(TEST_100_USERNAME, TEST_001_GROUPNAME);

    // @formatter:off
    mvc.perform(delete(DELETE_URL, request.getUuid()))
      .andExpect(status().isForbidden());
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = {"USER"}, username = TEST_100_USERNAME)
  public void deleteGroupRequestOfAnotherUser() throws Exception {

    GroupRequestDto request = savePendingGroupRequest("test_101", TEST_001_GROUPNAME);

    // @formatter:off
    mvc.perform(delete(DELETE_URL, request.getUuid()))
      .andExpect(status().isForbidden());
    // @formatter:on
  }

  @Test
  @WithAnonymousUser
  public void deleteGroupRequestAsAnonymous() throws Exception {
    
    GroupRequestDto request = savePendingGroupRequest(TEST_100_USERNAME, TEST_001_GROUPNAME);

    // @formatter:off
    mvc.perform(delete(DELETE_URL, request.getUuid()))
      .andExpect(status().isUnauthorized());
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = {"ADMIN"})
  public void deleteNotExitingGroupRequest() throws Exception {

    String fakeRequestUuid = UUID.randomUUID().toString();

    // @formatter:off
    mvc.perform(delete(DELETE_URL, fakeRequestUuid))
      .andExpect(status().isBadRequest());
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = {"ADMIN", "USER"})
  public void deletePendingGroupRequestAsUserWithBothRoles() throws Exception {
    
    GroupRequestDto request = savePendingGroupRequest(TEST_100_USERNAME, TEST_001_GROUPNAME);
    
    // @formatter:off
    mvc.perform(delete(DELETE_URL, request.getUuid()))
      .andExpect(status().isNoContent());
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = {"USER"}, username = TEST_100_USERNAME)
  public void exampleTest() throws Exception {

    GroupRequestDto request = buildGroupRequest(TEST_001_GROUPNAME);

    // @formatter:off
    mvc.perform(post(CREATE_URL)
        .contentType(MediaType.APPLICATION_JSON)
        .content(mapper.writeValueAsString(request)))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.username", equalTo(TEST_100_USERNAME)))
      .andExpect(jsonPath("$.groupName", equalTo(TEST_001_GROUPNAME)))
      .andExpect(jsonPath("$.status", equalTo(IamGroupRequestStatus.PENDING.name())));
    // @formatter:on

    assertThat(groupRequestRepo.findByUsernameAndGroup(TEST_100_USERNAME, TEST_001_GROUPNAME).isEmpty(), is(false));

    IamAccount account =
        accountRepo.findByUsername(TEST_100_USERNAME).orElseThrow(assertionError(EXPECTED_USER_NOT_FOUND));

    IamGroup group =
        groupRepo.findByName(TEST_001_GROUPNAME).orElseThrow(assertionError(EXPECTED_GROUP_NOT_FOUND));

    addAccountToGroup(account, group);

    assertThat(groupRequestRepo.findByUsernameAndGroup(TEST_100_USERNAME, TEST_001_GROUPNAME).isEmpty(), is(true));

  }

}
