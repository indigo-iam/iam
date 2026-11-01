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
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.lessThan;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.transaction.annotation.Transactional;

import com.google.common.collect.Lists;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.scim.model.ScimGroup;
import it.infn.mw.iam.api.scim.model.ScimGroupPatchRequest;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.test.config.ClockConfig;
import it.infn.mw.iam.test.util.clock.MutableClock;
import it.infn.mw.iam.test.util.oauth.OAuthTokenTestUtils;

@SpringBootTest(classes = {IamLoginService.class, ClockConfig.class},
    webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Transactional
class ScimGroupProvisioningPatchRemoveTests extends ScimGroupPatchUtils {

  static final String SCIM_CLIENT_ID = "scim-client-rw";
  static final String SCIM_CLIENT_SECRET = "secret";

  @Autowired
  MutableClock clock;

  ScimGroup engineers;
  ScimUser lennon, lincoln, kennedy;

  List<ScimUser> members;

  String scimAccessToken;

  @BeforeEach
  void initTests() throws Exception {

    scimAccessToken = OAuthTokenTestUtils.clientCredentialsToken(mvc, objectMapper, SCIM_CLIENT_ID,
        SCIM_CLIENT_SECRET, "scim:read", "scim:write");

    engineers = addTestGroup("engineers");
    lennon = addTestUser("john_lennon", "lennon@email.test", "John", "Lennon");
    lincoln = addTestUser("abraham_lincoln", "lincoln@email.test", "Abraham", "Lincoln");
    kennedy = addTestUser("jfk", "jfk@whitehouse.us", "John", "Kennedy");

    members = new ArrayList<>();
    members.add(lennon);
    members.add(lincoln);
    members.add(kennedy);

    addMembers(engineers, members);
  }

  @Test
  void testGroupPatchRemoveMember() throws Exception {

    ScimGroupPatchRequest patchRemoveRequest =
        getPatchRemoveUsersRequest(Lists.newArrayList(lennon));

    ScimGroup engineersBeforeUpdate = getGroup(engineers.getMeta().getLocation());

    assertIsGroupMember(lennon, engineersBeforeUpdate);
    assertIsGroupMember(lincoln, engineersBeforeUpdate);
    assertIsGroupMember(kennedy, engineersBeforeUpdate);

    // Mantiene l'attesa del test originale.
    Thread.sleep(1000);
    clock.advance(Duration.ofMillis(100));

    performScimWithToken(patch(engineers.getMeta().getLocation()).contentType(SCIM_CONTENT_TYPE)
      .content(objectMapper.writeValueAsString(patchRemoveRequest)), scimAccessToken)
        .andExpect(status().isNoContent());

    ScimGroup engineersAfterUpdate = getGroup(engineers.getMeta().getLocation());

    assertIsNotGroupMember(lennon, engineersAfterUpdate);
    assertIsGroupMember(lincoln, engineersAfterUpdate);
    assertIsGroupMember(kennedy, engineersAfterUpdate);

    long dateBeforeUpdate = engineersBeforeUpdate.getMeta().getLastModified().getTime();
    long dateAfterUpdate = engineersAfterUpdate.getMeta().getLastModified().getTime();

    assertThat(dateBeforeUpdate, lessThan(dateAfterUpdate));
  }

  @Test
  void testGroupPatchRemoveMultipleMembers() throws Exception {

    List<ScimUser> membersToRemove = new ArrayList<>();
    membersToRemove.add(lennon);
    membersToRemove.add(lincoln);

    ScimGroupPatchRequest patchReq = getPatchRemoveUsersRequest(membersToRemove);

    performScimWithToken(patch(engineers.getMeta().getLocation()).contentType(SCIM_CONTENT_TYPE)
      .content(objectMapper.writeValueAsString(patchReq)), scimAccessToken)
        .andExpect(status().isNoContent());

    ScimGroup updatedGroup = getGroup(engineers.getMeta().getLocation());

    assertIsGroupMember(kennedy, updatedGroup);
    assertIsNotGroupMember(lennon, updatedGroup);
    assertIsNotGroupMember(lincoln, updatedGroup);
  }

  @Test
  void testGroupPatchRemoveAllListOfMembers() throws Exception {

    List<ScimUser> membersToRemove = new ArrayList<>();
    membersToRemove.add(lennon);
    membersToRemove.add(lincoln);
    membersToRemove.add(kennedy);

    ScimGroupPatchRequest patchReq = getPatchRemoveUsersRequest(membersToRemove);

    performScimWithToken(patch(engineers.getMeta().getLocation()).contentType(SCIM_CONTENT_TYPE)
      .content(objectMapper.writeValueAsString(patchReq)), scimAccessToken)
        .andExpect(status().isNoContent());

    performScimWithToken(get(engineers.getMeta().getLocation() + "/members").contentType(SCIM_CONTENT_TYPE),
        scimAccessToken).andExpect(status().isOk())
          .andExpect(jsonPath("$.totalResults", is(0)))
          .andExpect(jsonPath("$.Resources", empty()));
  }

  @Test
  void testGroupPatchRemoveAllMembers() throws Exception {

    List<ScimUser> emptyMembers = new ArrayList<>();
    ScimGroupPatchRequest patchReq = getPatchRemoveUsersRequest(emptyMembers);

    performScimWithToken(patch(engineers.getMeta().getLocation()).contentType(SCIM_CONTENT_TYPE)
      .content(objectMapper.writeValueAsString(patchReq)), scimAccessToken)
        .andExpect(status().isNoContent());

    ScimGroup updatedGroup = getGroup(engineers.getMeta().getLocation());
    assertThat(updatedGroup.getMembers(), empty());
  }

  @Test
  void testGroupPatchRemoveMemberTwice() throws Exception {

    ScimGroupPatchRequest patchRemoveRequest =
        getPatchRemoveUsersRequest(Lists.newArrayList(lennon));

    performScimWithToken(patch(engineers.getMeta().getLocation()).contentType(SCIM_CONTENT_TYPE)
      .content(objectMapper.writeValueAsString(patchRemoveRequest)), scimAccessToken)
        .andExpect(status().isNoContent());

    ScimGroup engineersBeforeUpdate = getGroup(engineers.getMeta().getLocation());

    performScimWithToken(patch(engineers.getMeta().getLocation()).contentType(SCIM_CONTENT_TYPE)
      .content(objectMapper.writeValueAsString(patchRemoveRequest)), scimAccessToken)
        .andExpect(status().isNoContent());

    ScimGroup engineersAfterUpdate = getGroup(engineers.getMeta().getLocation());

    assertIsNotGroupMember(lennon, engineersAfterUpdate);

    assertThat(engineersBeforeUpdate.getMeta().getLastModified(),
        equalTo(engineersAfterUpdate.getMeta().getLastModified()));
  }
}
