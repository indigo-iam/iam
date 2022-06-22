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
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.UUID;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.requests.model.GroupRequestDto;
import it.infn.mw.iam.core.IamGroupRequestStatus;
import it.infn.mw.iam.core.IamNotificationType;
import it.infn.mw.iam.notification.service.NotificationStoreService;
import it.infn.mw.iam.persistence.model.IamEmailNotification;
import it.infn.mw.iam.persistence.repository.IamEmailNotificationRepository;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
public class GroupRequestsApproveTests extends GroupRequestsTestUtils {

  private final static String APPROVE_URL = "/iam/group_requests/{uuid}/approve";

  @Autowired
  private NotificationStoreService notificationService;

  @Autowired
  private IamEmailNotificationRepository emailRepository;

  @Autowired
  private MockMvc mvc;

  @Before
  public void setup() {
    emailRepository.deleteAll();
  }

  @Test
  @WithMockUser(roles = {"ADMIN"})
  public void approveGroupRequestAsAdmin() throws Exception {
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
    assertThat(result.getLastUpdateTime(), greaterThan(result.getCreationTime()));

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
  public void approveGroupRequestAsUser() throws Exception {
    GroupRequestDto request = savePendingGroupRequest(TEST_100_USERNAME, TEST_001_GROUPNAME);
    // @formatter:off
    mvc.perform(post(APPROVE_URL, request.getUuid()))
      .andExpect(status().isForbidden());
    // @formatter:on
  }

  @Test
  @WithAnonymousUser
  public void approveGroupRequestAsAnonymous() throws Exception {
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
  public void approveNotExitingGroupRequest() throws Exception {

    String fakeRequestUuid = UUID.randomUUID().toString();
    // @formatter:off
    mvc.perform(post(APPROVE_URL, fakeRequestUuid))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", containsString("does not exist")));
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = {"ADMIN"})
  public void approveAlreadyApprovedRequest() throws Exception {
    GroupRequestDto request = saveApprovedGroupRequest(TEST_100_USERNAME, TEST_001_GROUPNAME);
    // @formatter:off
    mvc.perform(post(APPROVE_URL, request.getUuid()))
    .andExpect(status().isBadRequest())
    .andExpect(jsonPath("$.error", containsString("Invalid group request transition")));
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = {"ADMIN"})
  public void approveRejectedRequest() throws Exception {
    GroupRequestDto request = saveRejectedGroupRequest(TEST_100_USERNAME, TEST_001_GROUPNAME);
    // @formatter:off
    mvc.perform(post(APPROVE_URL, request.getUuid()))
    .andExpect(status().isBadRequest())
    .andExpect(jsonPath("$.error", containsString("Invalid group request transition")));
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = {"ADMIN", "USER"})
  public void approveGroupRequestAsUserWithBothRoles() throws Exception {
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
}
