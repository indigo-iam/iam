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

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.requests.model.GroupRequestDto;
import it.infn.mw.iam.core.IamGroupRequestStatus;
import it.infn.mw.iam.core.IamNotificationType;
import it.infn.mw.iam.notification.service.NotificationStoreService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamEmailNotification;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.model.IamGroupRequest;
import it.infn.mw.iam.persistence.repository.IamEmailNotificationRepository;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
class GroupRequestsApproveTests extends GroupRequestsTestUtils {

  private final static String APPROVE_URL = "/iam/group_requests/{uuid}/approve";

  @Autowired
  private NotificationStoreService notificationService;

  @Autowired
  private IamEmailNotificationRepository emailRepository;

  @Autowired
  private MockMvc mvc;

  @BeforeEach
  void setup() {
    emailRepository.deleteAll();
  }

  @Test
  @WithMockUser(roles = {"ADMIN"})
  void approveGroupRequestAsAdmin() throws Exception {
    GroupRequestDto request = savePendingGroupRequest(TEST_100_USERNAME, TEST_001_GROUPNAME);
    // @formatter:off
    String response = mvc.perform(post(APPROVE_URL, request.getUuid()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.status", equalTo(IamGroupRequestStatus.APPROVED.name())))
      .andExpect(jsonPath("$.username", equalTo(TEST_100_USERNAME)))
      .andExpect(jsonPath("$.groupName", equalTo(TEST_001_GROUPNAME)))
      .andExpect(jsonPath("$.uuid", equalTo(request.getUuid())))
      .andExpect(jsonPath("$.lastUpdateTime").exists())
      .andExpect(jsonPath("$.lastUpdateTime").isNotEmpty())
      .andReturn()
      .getResponse()
      .getContentAsString();
    // @formatter:on

    GroupRequestDto result = mapper.readValue(response, GroupRequestDto.class);
    assertThat(result.getLastUpdateTime(), greaterThanOrEqualTo(result.getCreationTime()));

    int mailCount = notificationService.countPendingNotifications();
    assertThat(mailCount, equalTo(1));

    List<IamEmailNotification> mails =
        emailRepository.findByNotificationType(IamNotificationType.GROUP_MEMBERSHIP);
    assertThat(mails, hasSize(1));
    assertThat(mails.get(0).getBody(),
        containsString(format("membership request for the group %s", result.getGroupName())));
    assertThat(mails.get(0).getBody(), containsString(format("has been %s", result.getStatus())));
  }

  @Test
  @WithMockUser(roles = {"USER"})
  void approveGroupRequestAsUser() throws Exception {
    GroupRequestDto request = savePendingGroupRequest(TEST_100_USERNAME, TEST_001_GROUPNAME);
    // @formatter:off
    mvc.perform(post(APPROVE_URL, request.getUuid()))
      .andExpect(status().isForbidden());
    // @formatter:on
  }

  @Test
  @WithAnonymousUser
  void approveGroupRequestAsAnonymous() throws Exception {
    GroupRequestDto request = savePendingGroupRequest(TEST_100_USERNAME, TEST_001_GROUPNAME);
    // @formatter:off
    mvc.perform(post(APPROVE_URL, request.getUuid()))
      .andExpect(status().isUnauthorized())
      .andExpect(jsonPath("$.error", containsString("unauthorized")))
      .andExpect(jsonPath("$.error_description", containsString("Full authentication is required")));
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = {"ADMIN"})
  void approveNotExitingGroupRequest() throws Exception {

    String fakeRequestUuid = UUID.randomUUID().toString();
    // @formatter:off
    mvc.perform(post(APPROVE_URL, fakeRequestUuid))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", containsString("does not exist")));
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = {"ADMIN"})
  void approveAlreadyApprovedRequest() throws Exception {
    GroupRequestDto request = saveApprovedGroupRequest(TEST_100_USERNAME, TEST_001_GROUPNAME);
    // @formatter:off
    mvc.perform(post(APPROVE_URL, request.getUuid()))
    .andExpect(status().isBadRequest())
    .andExpect(jsonPath("$.error", containsString("Invalid group request transition")));
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = {"ADMIN"})
  void approveRejectedRequest() throws Exception {
    GroupRequestDto request = saveRejectedGroupRequest(TEST_100_USERNAME, TEST_001_GROUPNAME);
    // @formatter:off
    mvc.perform(post(APPROVE_URL, request.getUuid()))
    .andExpect(status().isBadRequest())
    .andExpect(jsonPath("$.error", containsString("Invalid group request transition")));
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = {"ADMIN", "USER"})
  void approveGroupRequestAsUserWithBothRoles() throws Exception {
    GroupRequestDto request = savePendingGroupRequest(TEST_100_USERNAME, TEST_001_GROUPNAME);
    // @formatter:off
    mvc.perform(post(APPROVE_URL, request.getUuid()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.status", equalTo(IamGroupRequestStatus.APPROVED.name())))
      .andExpect(jsonPath("$.username", equalTo(TEST_100_USERNAME)))
      .andExpect(jsonPath("$.groupName", equalTo(TEST_001_GROUPNAME)))
      .andExpect(jsonPath("$.uuid", equalTo(request.getUuid())))
      .andExpect(jsonPath("$.lastUpdateTime").exists())
      .andExpect(jsonPath("$.lastUpdateTime").isNotEmpty());
    // @formatter:on
  }

  @Transactional
  @Test
  @WithMockUser(roles = {"ADMIN"})
  void autoApproveParentGroupRequest() throws Exception {
    // Setup: Create parent-child group hierarchy
    IamGroup parentGroup = groupRepository.findByName(TEST_002_GROUPNAME).get();
    IamGroup childGroup = groupRepository.findByName(TEST_001_GROUPNAME).get();
  
    childGroup.setParentGroup(parentGroup);
    groupRepository.save(childGroup);
  
    IamAccount account = accountRepository.findByUsername(TEST_100_USERNAME).get();
  
    // Create a pending request for parent group
    IamGroupRequest parentRequest = new IamGroupRequest();
    parentRequest.setUuid(UUID.randomUUID().toString());
    parentRequest.setAccount(account);
    parentRequest.setGroup(parentGroup);
    parentRequest.setStatus(IamGroupRequestStatus.PENDING);
    parentRequest.setCreationTime(new java.util.Date());
    groupRequestRepository.save(parentRequest);
  
    // Create a pending request for child group
    IamGroupRequest childRequest = new IamGroupRequest();
    childRequest.setUuid(UUID.randomUUID().toString());
    childRequest.setAccount(account);
    childRequest.setGroup(childGroup);
    childRequest.setStatus(IamGroupRequestStatus.PENDING);
    childRequest.setCreationTime(new java.util.Date());
    groupRequestRepository.save(childRequest);
  
    // Approve child request - User will be automatically added to the parent group
    String response = mvc.perform(post(APPROVE_URL, childRequest.getUuid()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.status", equalTo(IamGroupRequestStatus.APPROVED.name())))
      .andExpect(jsonPath("$.groupName", equalTo(TEST_001_GROUPNAME)))
      .andExpect(jsonPath("$.username", equalTo(TEST_100_USERNAME)))
      .andReturn()
      .getResponse()
      .getContentAsString();
  
    GroupRequestDto result = mapper.readValue(response, GroupRequestDto.class);
  
    // Child request is approved
    assertThat(result.getStatus(), equalTo(IamGroupRequestStatus.APPROVED.toString()));
    assertThat(result.getGroupName(), equalTo(TEST_001_GROUPNAME));
    assertThat(result.getUsername(), equalTo(TEST_100_USERNAME));
  
    // Parent request will be approved automatically via recursive logic
    Optional<IamGroupRequest> hasParentRequest =
        groupRequestRepository.findByGroupIdAndAccountIdAndStatus(parentGroup.getId(), account.getId(), IamGroupRequestStatus.APPROVED);
  
    assertThat(hasParentRequest.isPresent(), equalTo(true));
    IamGroupRequest updatedParentRequest = hasParentRequest.get();
    assertThat(updatedParentRequest.getStatus(), equalTo(IamGroupRequestStatus.APPROVED));
    assertThat(updatedParentRequest.getAccount().getUsername(), equalTo(TEST_100_USERNAME));
  }

  @Transactional
  @Test
  @WithMockUser(roles = {"ADMIN"})
  void autoRejectChildGroupRequest() throws Exception {
    // Setup: parent-child relationship
    IamGroup parentGroup = groupRepository.findByName(TEST_002_GROUPNAME).get();
    IamGroup childGroup = groupRepository.findByName(TEST_001_GROUPNAME).get();
    childGroup.setParentGroup(parentGroup);
    groupRepository.save(childGroup);

    IamAccount account = accountRepository.findByUsername(TEST_100_USERNAME).get();

    // Parent request
    IamGroupRequest parentRequest = new IamGroupRequest();
    parentRequest.setUuid(UUID.randomUUID().toString());
    parentRequest.setAccount(account);
    parentRequest.setGroup(parentGroup);
    parentRequest.setStatus(IamGroupRequestStatus.PENDING);
    parentRequest.setCreationTime(new java.util.Date());
    groupRequestRepository.save(parentRequest);

    // Child request
    IamGroupRequest childRequest = new IamGroupRequest();
    childRequest.setUuid(UUID.randomUUID().toString());
    childRequest.setAccount(account);
    childRequest.setGroup(childGroup);
    childRequest.setStatus(IamGroupRequestStatus.PENDING);
    childRequest.setCreationTime(new java.util.Date());
    groupRequestRepository.save(childRequest);

    // Reject parent request -> should cascade to child
    String motivation = "Parent group request rejected";
    mvc.perform(post(REJECT_URL, parentRequest.getUuid()).param("motivation", motivation))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.status", equalTo(IamGroupRequestStatus.REJECTED.name())));

    Optional<IamGroupRequest> rejectedChild =
        groupRequestRepository.findByGroupIdAndAccountIdAndStatus(childGroup.getId(), account.getId(),
            IamGroupRequestStatus.REJECTED);
    assertThat(rejectedChild.isPresent(), equalTo(true));
  }
}
