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
package it.infn.mw.iam.test.scim.group.patch;

import static it.infn.mw.iam.api.scim.model.ScimConstants.SCIM_CONTENT_TYPE;
import static org.hamcrest.CoreMatchers.is;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.api.scim.model.ScimGroup;
import it.infn.mw.iam.api.scim.model.ScimGroupPatchRequest;
import it.infn.mw.iam.api.scim.model.ScimListResponse;
import it.infn.mw.iam.api.scim.model.ScimMemberRef;
import it.infn.mw.iam.api.scim.model.ScimResource;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.test.TestUtils;
import it.infn.mw.iam.test.api.requests.GroupRequestsTestUtils;
import it.infn.mw.iam.test.scim.ScimUtils;

public class ScimGroupPatchUtils extends GroupRequestsTestUtils {

  public static final String GROUP_URI = ScimUtils.getGroupsLocation();
  public static final String USER_URI = ScimUtils.getUsersLocation();

  public static final TypeReference<ScimListResponse<ScimMemberRef>> SCIM_MEMBER_LIST_TYPE =
      new TypeReference<ScimListResponse<ScimMemberRef>>() {};

  @Autowired
  protected ObjectMapper objectMapper;

  @Autowired
  protected MockMvc mvc;

  protected ResultActions performScimWithToken(MockHttpServletRequestBuilder request,
      String accessToken) throws Exception {

    return mvc.perform(request.header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken));
  }

  protected ResultActions performScimAsUser(MockHttpServletRequestBuilder request, String username,
      String... roles) throws Exception {

    return mvc.perform(request.with(user(username).roles(roles)));
  }

  protected ScimGroupPatchRequest getPatchAddUsersRequest(List<ScimUser> users) {

    return ScimGroupPatchRequest.builder().add(TestUtils.buildScimMemberRefList(users)).build();
  }

  protected ScimGroupPatchRequest getPatchRemoveUsersRequest(List<ScimUser> users) {

    return ScimGroupPatchRequest.builder().remove(TestUtils.buildScimMemberRefList(users)).build();
  }

  protected ScimGroupPatchRequest getPatchReplaceUsersRequest(List<ScimUser> users) {

    return ScimGroupPatchRequest.builder().replace(TestUtils.buildScimMemberRefList(users)).build();
  }

  protected ScimGroup addTestGroup(String displayName) throws Exception {

    ScimGroup group = ScimGroup.builder(displayName).build();
    return objectMapper.readValue(performScimAsUser(post(GROUP_URI).with(csrf().asHeader())
      .contentType(SCIM_CONTENT_TYPE)
      .content(objectMapper.writeValueAsString(group)), TEST_ADMIN, "USER", "ADMIN")
        .andExpect(status().isCreated())
        .andReturn()
        .getResponse()
        .getContentAsString(), ScimGroup.class);
  }

  protected ScimUser addTestUser(String userName, String email, String firstName, String LastName)
      throws Exception {

    ScimUser user =
        ScimUser.builder(userName).buildEmail(email).buildName(firstName, LastName).build();

    String result = performScimAsUser(post(USER_URI).with(csrf().asHeader())
      .contentType(SCIM_CONTENT_TYPE)
      .content(objectMapper.writeValueAsString(user)), TEST_ADMIN, "USER", "ADMIN")
        .andExpect(status().isCreated())
        .andReturn()
        .getResponse()
        .getContentAsString();

    return objectMapper.readValue(result, ScimUser.class);
  }

  protected void addMembers(ScimGroup group, List<ScimUser> members) throws Exception {

    ScimGroupPatchRequest patchAddReq = getPatchAddUsersRequest(members);

    performScimAsUser(patch(group.getMeta().getLocation()).with(csrf().asHeader())
      .contentType(SCIM_CONTENT_TYPE)
      .content(objectMapper.writeValueAsString(patchAddReq)), TEST_ADMIN, "USER", "ADMIN")
        .andExpect(status().isNoContent());

    getGroup(group.getMeta().getLocation());

    performScimAsUser(get(group.getMeta().getLocation() + "/members"), TEST_ADMIN, "USER", "ADMIN")
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.totalResults", is(members.size())));
  }

  protected void assertIsGroupMember(ScimUser user, ScimGroup group) throws Exception {

    performScimAsUser(get(group.getMeta().getLocation() + "/members"), TEST_ADMIN, "USER", "ADMIN")
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.Resources[?(@.value=='" + user.getId() + "')]").exists());
  }

  protected void assertIsNotGroupMember(ScimUser user, ScimGroup group) throws Exception {

    performScimAsUser(get(group.getMeta().getLocation() + "/members"), TEST_ADMIN, "USER", "ADMIN")
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.Resources[?(@.value=='" + user.getId() + "')]").doesNotExist());
  }

  protected ScimGroup getGroup(String location) throws Exception {

    return objectMapper.readValue(
        performScimAsUser(get(location).contentType(SCIM_CONTENT_TYPE), TEST_ADMIN, "USER", "ADMIN")
          .andExpect(status().isOk())
          .andReturn()
          .getResponse()
          .getContentAsString(),
        ScimGroup.class);
  }

  protected void deleteScimResource(ScimResource resource) throws Exception {

    performScimAsUser(delete(resource.getMeta().getLocation()).with(csrf().asHeader()), TEST_ADMIN,
        "USER", "ADMIN").andExpect(status().isNoContent());
  }
}
