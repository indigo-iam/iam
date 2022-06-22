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
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.lessThan;
import static org.hamcrest.MatcherAssert.assertThat;
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

import com.google.common.collect.Lists;

import it.infn.mw.iam.api.scim.model.ScimGroup;
import it.infn.mw.iam.api.scim.model.ScimGroupPatchRequest;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.test.util.WithMockOAuthUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@WithMockOAuthUser(clientId = "scim-client-rw", scopes = {"scim:read", "scim:write"})
public class ScimGroupProvisioningPatchRemoveTests extends ScimGroupPatchUtils {

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  private ScimGroup engineers;
  private ScimUser lennon, lincoln, kennedy;

  List<ScimUser> members;

  @Before
  public void initTests() throws Exception {
    mockOAuth2Filter.cleanupSecurityContext();
    engineers = addTestGroup("engineers");
    lennon = addTestUser("john_lennon", "lennon@email.test", "John", "Lennon");
    lincoln = addTestUser("abraham_lincoln", "lincoln@email.test", "Abraham", "Lincoln");
    kennedy = addTestUser("jfk", "jfk@whitehouse.us", "John", "Kennedy");

    members = new ArrayList<ScimUser>();
    members.add(lennon);
    members.add(lincoln);
    members.add(kennedy);

    addMembers(engineers, members);
  }

  @After
  public void teardownTests() throws Exception {
    deleteScimResource(lennon);
    deleteScimResource(lincoln);
    deleteScimResource(kennedy);
    deleteScimResource(engineers);
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @Test
  public void testGroupPatchRemoveMember() throws Exception {

    ScimGroupPatchRequest patchRemoveRequest =
        getPatchRemoveUsersRequest(Lists.newArrayList(lennon));

    ScimGroup engineersBeforeUpdate = getGroup(engineers.getMeta().getLocation());


    assertIsGroupMember(lennon, engineersBeforeUpdate);
    assertIsGroupMember(lincoln, engineersBeforeUpdate);
    assertIsGroupMember(kennedy, engineersBeforeUpdate);

    try {
      Thread.sleep(1000);
    } catch (InterruptedException e) {
    }

    //@formatter:off
    mvc.perform(patch(engineers.getMeta().getLocation())
        .contentType(SCIM_CONTENT_TYPE)
        .content(objectMapper.writeValueAsString(patchRemoveRequest)))
      .andExpect(status().isNoContent());
    //@formatter:on

    ScimGroup engineersAfterUpdate = getGroup(engineers.getMeta().getLocation());


    assertIsNotGroupMember(lennon, engineersAfterUpdate);
    assertIsGroupMember(lincoln, engineersAfterUpdate);
    assertIsGroupMember(kennedy, engineersAfterUpdate);

    final long dateBeforeUpdate = engineersBeforeUpdate.getMeta().getLastModified().getTime();
    final long dateAfterUpdate = engineersAfterUpdate.getMeta().getLastModified().getTime();

    assertThat(dateBeforeUpdate, lessThan(dateAfterUpdate));
  }

  @Test
  public void testGroupPatchRemoveMultipleMembers() throws Exception {

    List<ScimUser> membersToRemove = new ArrayList<ScimUser>();
    membersToRemove.add(lennon);
    membersToRemove.add(lincoln);

    ScimGroupPatchRequest patchReq = getPatchRemoveUsersRequest(membersToRemove);

    //@formatter:off
    mvc.perform(patch(engineers.getMeta().getLocation())
        .contentType(SCIM_CONTENT_TYPE)
        .content(objectMapper.writeValueAsString(patchReq)))
      .andExpect(status().isNoContent());
    //@formatter:on

    ScimGroup updatedGroup = getGroup(engineers.getMeta().getLocation());

    assertIsGroupMember(kennedy, updatedGroup);
    assertIsNotGroupMember(lennon, updatedGroup);
    assertIsNotGroupMember(lincoln, updatedGroup);
  }

  @Test
  public void testGroupPatchRemoveAllListOfMembers() throws Exception {

    List<ScimUser> membersToRemove = new ArrayList<ScimUser>();
    membersToRemove.add(lennon);
    membersToRemove.add(lincoln);
    membersToRemove.add(kennedy);

    ScimGroupPatchRequest patchReq = getPatchRemoveUsersRequest(membersToRemove);

    //@formatter:off
    mvc.perform(patch(engineers.getMeta().getLocation())
        .contentType(SCIM_CONTENT_TYPE)
        .content(objectMapper.writeValueAsString(patchReq)))
      .andExpect(status().isNoContent());
    //@formatter:on
    
    mvc
      .perform(get(engineers.getMeta().getLocation() + "/members").contentType(SCIM_CONTENT_TYPE))
        .andExpect(status().isOk())
      .andExpect(jsonPath("$.totalResults", is(0)))
      .andExpect(jsonPath("$.Resources", empty()));
  
  }

  @Test
  public void testGroupPatchRemoveAllMembers() throws Exception {

    List<ScimUser> emptyMembers = new ArrayList<ScimUser>();
    ScimGroupPatchRequest patchReq = getPatchRemoveUsersRequest(emptyMembers);

    //@formatter:off
    mvc.perform(patch(engineers.getMeta().getLocation())
        .contentType(SCIM_CONTENT_TYPE)
        .content(objectMapper.writeValueAsString(patchReq)))
      .andExpect(status().isNoContent());
    //@formatter:on

    ScimGroup updatedGroup = getGroup(engineers.getMeta().getLocation());
    assertThat(updatedGroup.getMembers(), empty());
  }

  @Test
  public void testGroupPatchRemogmveMemberTwice() throws Exception {

    ScimGroupPatchRequest patchRemoveRequest =
        getPatchRemoveUsersRequest(Lists.newArrayList(lennon));

    //@formatter:off
    mvc.perform(patch(engineers.getMeta().getLocation())
        .contentType(SCIM_CONTENT_TYPE)
        .content(objectMapper.writeValueAsString(patchRemoveRequest)))
      .andExpect(status().isNoContent());
    //@formatter:on

    ScimGroup engineersBeforeUpdate = getGroup(engineers.getMeta().getLocation());

    //@formatter:off
    mvc.perform(patch(engineers.getMeta().getLocation())
        .contentType(SCIM_CONTENT_TYPE)
        .content(objectMapper.writeValueAsString(patchRemoveRequest)))
      .andExpect(status().isNoContent());
    //@formatter:on

    ScimGroup engineersAfterUpdate = getGroup(engineers.getMeta().getLocation());

    assertIsNotGroupMember(lennon, engineersAfterUpdate);

    assertThat(engineersBeforeUpdate.getMeta().getLastModified(),
        equalTo(engineersAfterUpdate.getMeta().getLastModified()));
  }
}
