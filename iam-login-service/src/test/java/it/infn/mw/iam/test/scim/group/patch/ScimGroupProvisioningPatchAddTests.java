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
import static org.hamcrest.Matchers.equalTo;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.ArrayList;
import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.junit4.SpringRunner;

import it.infn.mw.iam.api.scim.model.ScimGroup;
import it.infn.mw.iam.api.scim.model.ScimGroupPatchRequest;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@WithMockOAuthUser(clientId = "scim-client-rw", scopes = {"scim:read", "scim:write"})
public class ScimGroupProvisioningPatchAddTests extends ScimGroupPatchUtils {

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  private ScimGroup engineers;
  private ScimUser lennon, lincoln;

  @Before
  public void setup() throws Exception {
    mockOAuth2Filter.cleanupSecurityContext();
    engineers = addTestGroup("engineers");
    lennon = addTestUser("john_lennon", "lennon@email.test", "John", "Lennon");
    lincoln = addTestUser("abraham_lincoln", "lincoln@email.test", "Abraham", "Lincoln");
  }

  @After
  public void teardown() throws Exception {
    deleteScimResource(lennon);
    deleteScimResource(lincoln);
    deleteScimResource(engineers);
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @Test
  public void testGroupPatchAddMember() throws Exception {

    List<ScimUser> members = new ArrayList<ScimUser>();
    members.add(lennon);

    ScimGroupPatchRequest patchReq = getPatchAddUsersRequest(members);

    //@formatter:off
    mvc.perform(patch(engineers.getMeta().getLocation())
        .contentType(SCIM_CONTENT_TYPE)
        .content(objectMapper.writeValueAsString(patchReq)))
      .andExpect(status().isNoContent());
    //@formatter:on

    assertIsGroupMember(lennon, engineers);
  }

  @Test
  public void testGroupPatchAddMembers() throws Exception {

    List<ScimUser> members = new ArrayList<ScimUser>();
    members.add(lennon);
    members.add(lincoln);

    ScimGroupPatchRequest patchAddReq = getPatchAddUsersRequest(members);

    //@formatter:off
    mvc.perform(patch(engineers.getMeta().getLocation())
        .contentType(SCIM_CONTENT_TYPE)
        .content(objectMapper.writeValueAsString(patchAddReq)))
      .andExpect(status().isNoContent());
    //@formatter:on

    mvc.perform(get(engineers.getMeta().getLocation()).contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.id", equalTo(engineers.getId())))
      .andExpect(jsonPath("$.displayName", equalTo(engineers.getDisplayName())))
      .andReturn()
      .getResponse()
      .getContentAsString();

    assertIsGroupMember(lennon, engineers);
    assertIsGroupMember(lincoln, engineers);

  }

  @Test
  public void testGroupPatchAddMembersWithFakeUser() throws Exception {

    List<ScimUser> members = new ArrayList<ScimUser>();
    ScimUser ringo = addTestUser("ringo", "mail@domain.com", "Ringo", "Star");
    members.add(lennon);
    members.add(ringo);

    mvc.perform(delete(ringo.getMeta().getLocation()));

    ScimGroupPatchRequest patchAddReq = getPatchAddUsersRequest(members);

    mvc.perform(patch(engineers.getMeta().getLocation()).contentType(SCIM_CONTENT_TYPE)
      .content(objectMapper.writeValueAsString(patchAddReq))).andExpect(status().isNotFound());

    mvc.perform(get(engineers.getMeta().getLocation()).contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.id", equalTo(engineers.getId())))
      .andExpect(jsonPath("$.displayName", equalTo(engineers.getDisplayName())))
      .andExpect(jsonPath("$.members").doesNotExist());
  }

  @Test
  public void testGroupPatchAddEmptyMembersList() throws Exception {

    ScimGroupPatchRequest patchAddReq = getPatchAddUsersRequest(new ArrayList<ScimUser>());

    mvc.perform(patch(engineers.getMeta().getLocation()).contentType(SCIM_CONTENT_TYPE)
      .content(objectMapper.writeValueAsString(patchAddReq))).andExpect(status().isNoContent());

    mvc.perform(get(engineers.getMeta().getLocation()).contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.id", equalTo(engineers.getId())))
      .andExpect(jsonPath("$.displayName", equalTo(engineers.getDisplayName())))
      .andExpect(jsonPath("$.members").doesNotExist());
  }
}
