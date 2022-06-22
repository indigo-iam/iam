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

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

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
import it.infn.mw.iam.core.IamGroupRequestStatus;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
public class GroupRequestsGroupManagerTests extends GroupRequestsTestUtils {
  private static final String GROUP_MANAGER_USER = "test_200";

  private static final String USER_ROLE = "USER";
  private static final String GROUP_MANAGER_ROLE_001 = "GM:" + TEST_001_GROUP_UUID;
  private static final String GROUP_MANAGER_ROLE_002 = "GM:" + TEST_002_GROUP_UUID;

  private static final String APPROVE_URL = "/iam/group_requests/{uuid}/approve";
  private static final String REJECT_URL = "/iam/group_requests/{uuid}/reject";
  private static final String GET_DETAILS_URL = "/iam/group_requests/{uuid}";
  private static final String LIST_REQUESTS_URL = "/iam/group_requests";
  private final static String DELETE_URL = "/iam/group_requests/{uuid}";

  @Autowired
  private MockMvc mvc;

  @Test
  @WithMockUser(username = GROUP_MANAGER_USER, roles = {GROUP_MANAGER_ROLE_001, USER_ROLE})
  public void testGroupManagerCanAccessGroupPendingRequest() throws Exception {

    GroupRequestDto request = savePendingGroupRequest(TEST_100_USERNAME, TEST_001_GROUPNAME);

 // @formatter:off
    mvc.perform(get(GET_DETAILS_URL, request.getUuid()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.uuid", equalTo(request.getUuid())))
      .andExpect(jsonPath("$.username", equalTo(request.getUsername())))
      .andExpect(jsonPath("$.groupName", equalTo(request.getGroupName())))
      .andExpect(jsonPath("$.status", equalTo(request.getStatus())))
      .andExpect(jsonPath("$.notes", equalTo(request.getNotes())));
    // @formatter:on
  }

  @Test
  @WithMockUser(username = GROUP_MANAGER_USER,
      roles = {GROUP_MANAGER_ROLE_001, GROUP_MANAGER_ROLE_002, USER_ROLE})
  public void testGroupManagercanListPendingRequestForManagedGroups() throws Exception {
    savePendingGroupRequest(TEST_100_USERNAME, TEST_001_GROUPNAME);
    savePendingGroupRequest(TEST_101_USERNAME, TEST_001_GROUPNAME);
    savePendingGroupRequest(TEST_102_USERNAME, TEST_001_GROUPNAME);

    savePendingGroupRequest(TEST_100_USERNAME, TEST_002_GROUPNAME);
    savePendingGroupRequest(TEST_101_USERNAME, TEST_002_GROUPNAME);

    mvc.perform(get(LIST_REQUESTS_URL).contentType(MediaType.APPLICATION_JSON))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.totalResults", equalTo(5)))
      .andExpect(jsonPath("$.startIndex", equalTo(1)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(5)))
      .andExpect(jsonPath("$.Resources", hasSize(5)))
      .andExpect(jsonPath("$.Resources[?(@.groupName == 'Test-001')]", hasSize(3)))
      .andExpect(jsonPath("$.Resources[?(@.groupName == 'Test-002')]", hasSize(2)))
      .andExpect(jsonPath("$.Resources[?(@.username == 'test_100')]", hasSize(2)))
      .andExpect(jsonPath("$.Resources[?(@.username == 'test_101')]", hasSize(2)))
      .andExpect(jsonPath("$.Resources[?(@.username == 'test_102')]", hasSize(1)));


  }

  @Test
  @WithMockUser(username = GROUP_MANAGER_USER, roles = {GROUP_MANAGER_ROLE_001, USER_ROLE})
  public void testGroupManagercanListPendingRequestForManagedGroup() throws Exception {
    savePendingGroupRequest(TEST_100_USERNAME, TEST_001_GROUPNAME);
    savePendingGroupRequest(TEST_101_USERNAME, TEST_001_GROUPNAME);
    savePendingGroupRequest(TEST_102_USERNAME, TEST_001_GROUPNAME);

    savePendingGroupRequest(TEST_100_USERNAME, TEST_002_GROUPNAME);
    savePendingGroupRequest(TEST_101_USERNAME, TEST_002_GROUPNAME);

    mvc.perform(get(LIST_REQUESTS_URL).contentType(MediaType.APPLICATION_JSON))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.totalResults", equalTo(3)))
      .andExpect(jsonPath("$.startIndex", equalTo(1)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(3)))
      .andExpect(jsonPath("$.Resources", hasSize(3)))
      .andExpect(jsonPath("$.Resources[?(@.groupName == 'Test-001')]", hasSize(3)))
      .andExpect(jsonPath("$.Resources[?(@.username == 'test_100')]", hasSize(1)))
      .andExpect(jsonPath("$.Resources[?(@.username == 'test_101')]", hasSize(1)))
      .andExpect(jsonPath("$.Resources[?(@.username == 'test_102')]", hasSize(1)));

  }

  @Test
  @WithMockUser(username = GROUP_MANAGER_USER, roles = {GROUP_MANAGER_ROLE_002, USER_ROLE})
  public void testGroupManagercanListPendingRequestForManagedGroup2() throws Exception {
    savePendingGroupRequest(TEST_100_USERNAME, TEST_001_GROUPNAME);
    savePendingGroupRequest(TEST_101_USERNAME, TEST_001_GROUPNAME);
    savePendingGroupRequest(TEST_102_USERNAME, TEST_001_GROUPNAME);

    mvc.perform(get(LIST_REQUESTS_URL).contentType(MediaType.APPLICATION_JSON))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.totalResults", equalTo(0)))
      .andExpect(jsonPath("$.Resources", hasSize(0)));
  }

  @Test
  @WithMockUser(username = GROUP_MANAGER_USER, roles = {GROUP_MANAGER_ROLE_001, USER_ROLE})
  public void testGroupManagerCanApproveRequestsForManagedGroup() throws Exception {

    GroupRequestDto request = savePendingGroupRequest(TEST_100_USERNAME, TEST_001_GROUPNAME);

    mvc.perform(post(APPROVE_URL, request.getUuid()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.status", equalTo(IamGroupRequestStatus.APPROVED.name())))
      .andExpect(jsonPath("$.username", equalTo(TEST_100_USERNAME)))
      .andExpect(jsonPath("$.groupName", equalTo(TEST_001_GROUPNAME)))
      .andExpect(jsonPath("$.uuid", equalTo(request.getUuid())))
      .andExpect(jsonPath("$.lastUpdateTime").exists())
      .andExpect(jsonPath("$.lastUpdateTime").isNotEmpty());

    GroupRequestDto otherRequest = savePendingGroupRequest(TEST_100_USERNAME, TEST_002_GROUPNAME);

    mvc.perform(post(APPROVE_URL, otherRequest.getUuid())).andExpect(status().isForbidden());
  }

  @Test
  @WithMockUser(username = GROUP_MANAGER_USER, roles = {GROUP_MANAGER_ROLE_001, USER_ROLE})
  public void testGroupManagerCanRejectRequestsForManagedGroup() throws Exception {

    GroupRequestDto request = savePendingGroupRequest(TEST_100_USERNAME, TEST_001_GROUPNAME);

    mvc.perform(post(REJECT_URL, request.getUuid()).param("motivation", TEST_REJECT_MOTIVATION))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.status", equalTo(IamGroupRequestStatus.REJECTED.name())))
      .andExpect(jsonPath("$.username", equalTo(TEST_100_USERNAME)))
      .andExpect(jsonPath("$.groupName", equalTo(TEST_001_GROUPNAME)))
      .andExpect(jsonPath("$.uuid", equalTo(request.getUuid())))
      .andExpect(jsonPath("$.lastUpdateTime").exists())
      .andExpect(jsonPath("$.lastUpdateTime").isNotEmpty());

    GroupRequestDto otherRequest = savePendingGroupRequest(TEST_100_USERNAME, TEST_002_GROUPNAME);

    mvc
      .perform(post(REJECT_URL, otherRequest.getUuid()).param("motivation", TEST_REJECT_MOTIVATION))
      .andExpect(status().isForbidden());
  }

  @Test
  @WithMockUser(username = GROUP_MANAGER_USER, roles = {GROUP_MANAGER_ROLE_001, USER_ROLE})
  public void testGroupManagerCanDeleteRequestsForManagedGroup() throws Exception {

    GroupRequestDto req1 = savePendingGroupRequest(TEST_100_USERNAME, TEST_001_GROUPNAME);
    GroupRequestDto req2 = saveApprovedGroupRequest(TEST_101_USERNAME, TEST_001_GROUPNAME);
    GroupRequestDto req3 = saveRejectedGroupRequest(TEST_102_USERNAME, TEST_001_GROUPNAME);

    GroupRequestDto otherReq = savePendingGroupRequest(TEST_100_USERNAME, TEST_002_GROUPNAME);

    mvc.perform(delete(DELETE_URL, req1.getUuid())).andExpect(status().isNoContent());
    mvc.perform(delete(DELETE_URL, req2.getUuid())).andExpect(status().isNoContent());
    mvc.perform(delete(DELETE_URL, req3.getUuid())).andExpect(status().isNoContent());

    mvc.perform(delete(DELETE_URL, otherReq.getUuid())).andExpect(status().isForbidden());
  }
}
