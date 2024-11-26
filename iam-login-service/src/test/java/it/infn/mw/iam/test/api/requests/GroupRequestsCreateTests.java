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
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;

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
public class GroupRequestsCreateTests extends GroupRequestsTestUtils {

  private final static String CREATE_URL = "/iam/group_requests";

  @Value("${iam.baseUrl}")
  private String baseUrl;

  @Autowired
  private ObjectMapper mapper;

  @Autowired
  private NotificationStoreService notificationService;

  @Autowired
  private IamEmailNotificationRepository emailRepository;

  @Autowired
  private MockMvc mvc;

  @Before
  public void setup() {
    notificationService.clearAllNotifications();
  }

  @Test
  @WithMockUser(roles = {"ADMIN"}, username = TEST_ADMIN)
  public void createGroupRequestAsAdmin() throws Exception {
    GroupRequestDto request = buildGroupRequest(TEST_001_GROUPNAME);
    
    // @formatter:off
    mvc.perform(post(CREATE_URL)
        .contentType(MediaType.APPLICATION_JSON)
        .content(mapper.writeValueAsString(request)))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.username", equalTo(TEST_ADMIN)))
      .andExpect(jsonPath("$.userUuid", equalTo(TEST_ADMIN_UUID)))
      .andExpect(jsonPath("$.userFullName", equalTo(TEST_ADMIN_FULL_NAME)))
      .andExpect(jsonPath("$.groupName", equalTo(TEST_001_GROUPNAME)))
      .andExpect(jsonPath("$.status", equalTo(IamGroupRequestStatus.PENDING.name())));
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = {"USER"}, username = TEST_100_USERNAME)
  public void createGroupRequestAsUser() throws Exception {
    
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
    int mailCount = notificationService.countPendingNotifications();
    assertThat(mailCount, equalTo(1));

    List<IamEmailNotification> mails =
        emailRepository.findByNotificationType(IamNotificationType.GROUP_MEMBERSHIP);
    assertThat(mails, hasSize(1));
    assertThat(mails.get(0).getBody(), containsString(format("Username: %s", TEST_100_USERNAME)));
    assertThat(mails.get(0).getBody(), containsString(format("Group: %s", request.getGroupName())));
    assertThat(mails.get(0).getBody(), containsString(request.getNotes()));
    assertThat(mails.get(0).getBody(), containsString(baseUrl));
  }

  @Test
  @WithAnonymousUser
  public void createGroupRequestAsAnonymous() throws Exception {
    GroupRequestDto request = buildGroupRequest(TEST_001_GROUPNAME);
    
    // @formatter:off
    mvc.perform(post(CREATE_URL)
        .contentType(MediaType.APPLICATION_JSON)
        .content(mapper.writeValueAsString(request)))
      .andExpect(status().isUnauthorized());
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = {"USER"}, username = TEST_100_USERNAME)
  public void createGroupRequestWitInvalidNotes() throws Exception {
    GroupRequestDto request = buildGroupRequest(TEST_001_GROUPNAME);
    request.setNotes(null);
    // @formatter:off
    mvc.perform(post(CREATE_URL)
        .contentType(MediaType.APPLICATION_JSON)
        .content(mapper.writeValueAsString(request)))
      .andExpect(status().isBadRequest());
    // @formatter:on

    request.setNotes("");
    // @formatter:off
    mvc.perform(post(CREATE_URL)
        .contentType(MediaType.APPLICATION_JSON)
        .content(mapper.writeValueAsString(request)))
      .andExpect(status().isBadRequest());
    // @formatter:on

    request.setNotes("   ");
    // @formatter:off
    mvc.perform(post(CREATE_URL)
        .contentType(MediaType.APPLICATION_JSON)
        .content(mapper.writeValueAsString(request)))
      .andExpect(status().isBadRequest());
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = {"USER"}, username = TEST_100_USERNAME)
  public void createGroupRequestWithInvalidGroup() throws Exception {
    GroupRequestDto request = buildGroupRequest(TEST_001_GROUPNAME);
    request.setGroupName("");
    // @formatter:off
    mvc.perform(post(CREATE_URL)
        .contentType(MediaType.APPLICATION_JSON)
        .content(mapper.writeValueAsString(request)))
      .andExpect(status().isBadRequest());
    // @formatter:on

    request.setGroupName("fake_group");
    // @formatter:off
    mvc.perform(post(CREATE_URL)
        .contentType(MediaType.APPLICATION_JSON)
        .content(mapper.writeValueAsString(request)))
      .andExpect(status().isBadRequest());
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = {"USER"}, username = TEST_100_USERNAME)
  public void createGroupRequestAlreadyExists() throws Exception {
    GroupRequestDto request = buildGroupRequest(TEST_001_GROUPNAME);
    savePendingGroupRequest(TEST_100_USERNAME, TEST_001_GROUPNAME);
    // @formatter:off
    mvc.perform(post(CREATE_URL)
        .contentType(MediaType.APPLICATION_JSON)
        .content(mapper.writeValueAsString(request)))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", containsString("already exist")));
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = {"USER"}, username = "test")
  public void createGroupRequestUserAlreadyMember() throws Exception {
    GroupRequestDto request = buildGroupRequest("Analysis");
    // @formatter:off
    mvc.perform(post(CREATE_URL)
        .contentType(MediaType.APPLICATION_JSON)
        .content(mapper.writeValueAsString(request)))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", containsString("already member")));
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = {"ADMIN", "USER"}, username = TEST_100_USERNAME)
  public void createGroupRequestAsUserWithBothRoles() throws Exception {
    
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
  }
}
