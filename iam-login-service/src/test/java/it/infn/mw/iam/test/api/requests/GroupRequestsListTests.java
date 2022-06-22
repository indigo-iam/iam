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
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.core.type.TypeReference;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.requests.model.GroupRequestDto;
import it.infn.mw.iam.core.IamGroupRequestStatus;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
public class GroupRequestsListTests extends GroupRequestsTestUtils {

  private final static String LIST_REQUESTS_URL = "/iam/group_requests/";

  @Autowired
  private MockMvc mvc;

  private final static String USER_100 = TEST_100_USERNAME;
  private final static String USER_101 = "test_101";

  private final static String GROUP_01 = TEST_001_GROUPNAME;
  private final static String GROUP_02 = "Test-002";
  private final static String GROUP_03 = "Test-003";

  @Before
  public void setup() {
    savePendingGroupRequest(USER_100, GROUP_01);
    savePendingGroupRequest(USER_101, GROUP_01);

    saveApprovedGroupRequest(USER_100, GROUP_02);
    saveApprovedGroupRequest(USER_101, GROUP_02);

    saveRejectedGroupRequest(USER_100, GROUP_03);
    saveRejectedGroupRequest(USER_101, GROUP_03);
  }

  @Test
  @WithMockUser(roles = {"ADMIN"}, username = TEST_ADMIN)
  public void listGroupRequestAsAdmin() throws Exception {
    
    // @formatter:off
    mvc.perform(get(LIST_REQUESTS_URL)
        .contentType(MediaType.APPLICATION_JSON))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.totalResults", equalTo(6)))
      .andExpect(jsonPath("$.startIndex", equalTo(1)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(6)))
      .andExpect(jsonPath("$.Resources", hasSize(6)));
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = {"ADMIN"}, username = TEST_ADMIN)
  public void filterByUsernameAsAdmin() throws Exception {
    // @formatter:off
    String response = mvc.perform(get(LIST_REQUESTS_URL)
        .contentType(MediaType.APPLICATION_JSON)
        .param("username", USER_101))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.totalResults", equalTo(3)))
      .andExpect(jsonPath("$.startIndex", equalTo(1)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(3)))
      .andExpect(jsonPath("$.Resources", hasSize(3)))
      .andReturn()
      .getResponse()
      .getContentAsString();
    // @formatter:on

    ListResponseDTO<GroupRequestDto> result =
        mapper.readValue(response, new TypeReference<ListResponseDTO<GroupRequestDto>>() {});

    for (GroupRequestDto elem : result.getResources()) {
      assertThat(elem.getUsername(), equalTo(USER_101));
    }
  }

  @Test
  @WithMockUser(roles = {"ADMIN"}, username = TEST_ADMIN)
  public void filterByStatusAsAdmin() throws Exception {
    // @formatter:off
    String response = mvc.perform(get(LIST_REQUESTS_URL)
        .contentType(MediaType.APPLICATION_JSON)
        .param("status", IamGroupRequestStatus.PENDING.name()))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.totalResults", equalTo(2)))
      .andExpect(jsonPath("$.startIndex", equalTo(1)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(2)))
      .andExpect(jsonPath("$.Resources", hasSize(2)))
      .andReturn()
      .getResponse()
      .getContentAsString();
    // @formatter:on

    ListResponseDTO<GroupRequestDto> result =
        mapper.readValue(response, new TypeReference<ListResponseDTO<GroupRequestDto>>() {});

    for (GroupRequestDto elem : result.getResources()) {
      assertThat(elem.getStatus(), equalTo(IamGroupRequestStatus.PENDING.name()));
    }
  }

  @Test
  @WithMockUser(roles = {"ADMIN"}, username = TEST_ADMIN)
  public void filterByGroupAsAdmin() throws Exception {
    // @formatter:off
    String response = mvc.perform(get(LIST_REQUESTS_URL)
        .contentType(MediaType.APPLICATION_JSON)
        .param("groupName", GROUP_02))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.totalResults", equalTo(2)))
      .andExpect(jsonPath("$.startIndex", equalTo(1)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(2)))
      .andExpect(jsonPath("$.Resources", hasSize(2)))
      .andReturn()
      .getResponse()
      .getContentAsString();
    // @formatter:on

    ListResponseDTO<GroupRequestDto> result =
        mapper.readValue(response, new TypeReference<ListResponseDTO<GroupRequestDto>>() {});

    for (GroupRequestDto elem : result.getResources()) {
      assertThat(elem.getGroupName(), equalTo(GROUP_02));
    }
  }

  @Test
  @WithMockUser(roles = {"USER"}, username = USER_100)
  public void listGroupRequestAsUser() throws Exception {
    // @formatter:off
    String response = mvc.perform(get(LIST_REQUESTS_URL)
        .contentType(MediaType.APPLICATION_JSON))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.totalResults", equalTo(3)))
      .andExpect(jsonPath("$.startIndex", equalTo(1)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(3)))
      .andExpect(jsonPath("$.Resources", hasSize(3)))
      .andReturn()
      .getResponse()
      .getContentAsString();
    // @formatter:on

    ListResponseDTO<GroupRequestDto> result =
        mapper.readValue(response, new TypeReference<ListResponseDTO<GroupRequestDto>>() {});

    for (GroupRequestDto elem : result.getResources()) {
      assertThat(elem.getUsername(), equalTo(USER_100));
    }
  }

  @Test
  @WithMockUser(roles = {"USER"}, username = USER_100)
  public void listGroupRequestOfAnotherUserIgnoreFilter() throws Exception {
    // @formatter:off
    String response = mvc.perform(get(LIST_REQUESTS_URL)
        .contentType(MediaType.APPLICATION_JSON)
        .param("username", USER_101))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();
    // @formatter:on

    ListResponseDTO<GroupRequestDto> result =
        mapper.readValue(response, new TypeReference<ListResponseDTO<GroupRequestDto>>() {});

    for (GroupRequestDto elem : result.getResources()) {
      assertThat(elem.getUsername(), equalTo(USER_100));
    }
  }

  @Test
  @WithAnonymousUser
  public void listGroupRequestAsAnonymous() throws Exception {
    // @formatter:off
    mvc.perform(get(LIST_REQUESTS_URL)
        .contentType(MediaType.APPLICATION_JSON))
      .andExpect(status().isUnauthorized());
    // @formatter:on
  }

  @Test
  @WithMockUser(roles = {"ADMIN"}, username = TEST_ADMIN)
  public void filterByUsernameAndStatusAsAdmin() throws Exception {
    String testStatus = IamGroupRequestStatus.PENDING.name();
    // @formatter:off
    String response = mvc.perform(get(LIST_REQUESTS_URL)
        .contentType(MediaType.APPLICATION_JSON)
        .param("username", USER_100)
        .param("status", testStatus))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.totalResults", equalTo(1)))
      .andExpect(jsonPath("$.startIndex", equalTo(1)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(1)))
      .andExpect(jsonPath("$.Resources", hasSize(1)))
      .andReturn()
      .getResponse()
      .getContentAsString();
    // @formatter:on

    ListResponseDTO<GroupRequestDto> result =
        mapper.readValue(response, new TypeReference<ListResponseDTO<GroupRequestDto>>() {});

    for (GroupRequestDto elem : result.getResources()) {
      assertThat(elem.getUsername(), equalTo(USER_100));
      assertThat(elem.getStatus(), equalTo(testStatus));
    }
  }

  @Test
  @WithMockUser(roles = {"ADMIN"}, username = TEST_ADMIN)
  public void filterByGroupAndStatusAsAdmin() throws Exception {
    String testStatus = IamGroupRequestStatus.PENDING.name();
    // @formatter:off
    String response = mvc.perform(get(LIST_REQUESTS_URL)
        .contentType(MediaType.APPLICATION_JSON)
        .param("groupName", GROUP_01)
        .param("status", testStatus))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.totalResults", equalTo(2)))
      .andExpect(jsonPath("$.startIndex", equalTo(1)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(2)))
      .andExpect(jsonPath("$.Resources", hasSize(2)))
      .andReturn()
      .getResponse()
      .getContentAsString();
    // @formatter:on

    ListResponseDTO<GroupRequestDto> result =
        mapper.readValue(response, new TypeReference<ListResponseDTO<GroupRequestDto>>() {});

    for (GroupRequestDto elem : result.getResources()) {
      assertThat(elem.getGroupName(), equalTo(GROUP_01));
      assertThat(elem.getStatus(), equalTo(testStatus));
    }
  }

  @Test
  @WithMockUser(roles = {"ADMIN", "USER"}, username = TEST_ADMIN)
  public void listRequestAsUserWithBothRoles() throws Exception {
    // @formatter:off
    mvc.perform(get(LIST_REQUESTS_URL)
        .contentType(MediaType.APPLICATION_JSON))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.totalResults", equalTo(6)))
      .andExpect(jsonPath("$.startIndex", equalTo(1)))
      .andExpect(jsonPath("$.itemsPerPage", equalTo(6)))
      .andExpect(jsonPath("$.Resources", hasSize(6)));
    // @formatter:on
  }
}
