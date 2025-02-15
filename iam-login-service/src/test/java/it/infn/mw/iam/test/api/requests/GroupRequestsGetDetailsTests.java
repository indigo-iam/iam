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

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.UUID;

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
import it.infn.mw.iam.api.requests.service.GroupRequestsService;
import it.infn.mw.iam.core.IamGroupRequestStatus;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
public class GroupRequestsGetDetailsTests extends GroupRequestsTestUtils {

  @Autowired
  private MockMvc mvc;

  @Autowired
  private GroupRequestsService groupRequestsService;

  @Test
  @WithMockUser(roles = {"ADMIN"}, username = TEST_ADMIN)
  public void getGroupRequestDetailsAsAdmin() throws Exception {

    GroupRequestDto request = buildGroupRequest(TEST_ADMIN_UUID, TEST_001_GROUPNAME);
    request = groupRequestsService.createGroupRequest(request);

    mvc.perform(get(GET_DETAILS_URL, request.getUuid()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.uuid", equalTo(request.getUuid())))
      .andExpect(jsonPath("$.username", equalTo(request.getUsername())))
      .andExpect(jsonPath("$.groupName", equalTo(request.getGroupName())))
      .andExpect(jsonPath("$.status", equalTo(request.getStatus())))
      .andExpect(jsonPath("$.notes", equalTo(request.getNotes())));
  }

  @Test
  @WithMockUser(roles = {"USER"}, username = TEST_100_USERNAME)
  public void getGroupRequestDetailsAsUser() throws Exception {

    GroupRequestDto request = buildGroupRequest(TEST_100_USERUUID, TEST_001_GROUPNAME);
    request = groupRequestsService.createGroupRequest(request);

    mvc.perform(get(GET_DETAILS_URL, request.getUuid()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.userUuid", equalTo(TEST_100_USERUUID)))
      .andExpect(jsonPath("$.groupName", equalTo(TEST_001_GROUPNAME)))
      .andExpect(jsonPath("$.status", equalTo(IamGroupRequestStatus.PENDING.name())));
  }

  @Test
  @WithMockUser(roles = {"USER"}, username = TEST_100_USERNAME)
  public void getGroupRequestDetailsOfAnotherUser() throws Exception {
    GroupRequestDto request = savePendingGroupRequest("test_101", TEST_001_GROUPNAME);
    mvc.perform(get(GET_DETAILS_URL, request.getUuid())).andExpect(status().isForbidden());
  }

  @Test
  @WithAnonymousUser
  public void getGroupRequestDetailsAsAnonymous() throws Exception {
    GroupRequestDto request = savePendingGroupRequest(TEST_100_USERNAME, TEST_001_GROUPNAME);
    mvc.perform(get(GET_DETAILS_URL, request.getUuid()))
      .andExpect(status().isUnauthorized())
      .andExpect(jsonPath("$.error", containsString("unauthorized")))
      .andExpect(
          jsonPath("$.error_description", containsString("Full authentication is required")));
  }

  @Test
  @WithMockUser(roles = {"ADMIN"})
  public void getDetailsOfNotExitingGroupRequest() throws Exception {

    String fakeRequestUuid = UUID.randomUUID().toString();
    mvc.perform(get(GET_DETAILS_URL, fakeRequestUuid))
      .andExpect(status().isBadRequest())
      .andExpect(jsonPath("$.error", containsString("does not exist")));
  }

  @Test
  @WithMockUser(roles = {"ADMIN", "USER"})
  public void getGroupRequestDetailsAsUserWithBothRoles() throws Exception {
    GroupRequestDto request = savePendingGroupRequest(TEST_100_USERNAME, TEST_001_GROUPNAME);
    mvc.perform(get(GET_DETAILS_URL, request.getUuid()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.uuid", equalTo(request.getUuid())))
      .andExpect(jsonPath("$.username", equalTo(request.getUsername())))
      .andExpect(jsonPath("$.groupName", equalTo(request.getGroupName())))
      .andExpect(jsonPath("$.status", equalTo(request.getStatus())))
      .andExpect(jsonPath("$.notes", equalTo(request.getNotes())));
  }

}
