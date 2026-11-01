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
import static org.hamcrest.Matchers.equalTo;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Clock;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.function.Supplier;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.scim.converter.GroupConverter;
import it.infn.mw.iam.api.scim.converter.UserConverter;
import it.infn.mw.iam.api.scim.model.ScimGroup;
import it.infn.mw.iam.api.scim.model.ScimGroupPatchRequest;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamGroupRepository;
import it.infn.mw.iam.persistence.repository.IamGroupRequestRepository;
import it.infn.mw.iam.test.util.oauth.OAuthTokenTestUtils;

@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Transactional
class ScimGroupProvisioningPatchAddTests extends ScimGroupPatchUtils {

  static final String SCIM_CLIENT_ID = "scim-client-rw";
  static final String SCIM_CLIENT_SECRET = "secret";

  @Autowired
  private IamAccountRepository iamAccountRepo;

  @Autowired
  private IamGroupRepository iamGroupRepo;

  @Autowired
  private UserConverter userConverter;

  @Autowired
  private GroupConverter groupConverter;

  @Autowired
  private IamGroupRequestRepository groupRequestRepo;

  @Autowired
  Clock clock;

  ScimGroup engineers;
  ScimUser lennon, lincoln;
  String scimAccessToken;

  private Supplier<AssertionError> assertionError(String message) {
    return () -> new AssertionError(message);
  }

  @BeforeEach
  void setup() throws Exception {

    scimAccessToken = OAuthTokenTestUtils.clientCredentialsToken(mvc, objectMapper, SCIM_CLIENT_ID,
        SCIM_CLIENT_SECRET, "scim:read", "scim:write");

    engineers = addTestGroup("engineers");
    lennon = addTestUser("john_lennon", "lennon@email.test", "John", "Lennon");
    lincoln = addTestUser("abraham_lincoln", "lincoln@email.test", "Abraham", "Lincoln");
  }

  @Test
  void testGroupPatchAddMember() throws Exception {

    List<ScimUser> members = new ArrayList<>();
    members.add(lennon);

    ScimGroupPatchRequest patchReq = getPatchAddUsersRequest(members);

    performScimWithToken(patch(engineers.getMeta().getLocation()).contentType(SCIM_CONTENT_TYPE)
      .content(objectMapper.writeValueAsString(patchReq)), scimAccessToken)
        .andExpect(status().isNoContent());

    assertIsGroupMember(lennon, engineers);
  }

  @Test
  void testGroupPatchAddMemberAndDeleteGMR() throws Exception {

    List<ScimUser> members = new ArrayList<>();

    IamAccount account =
        iamAccountRepo.findByUsername(TEST_100_USERNAME).orElseThrow(assertionError("Not found"));
    ScimUser scimUser = userConverter.dtoFromEntity(account);

    IamAccount account2 =
        iamAccountRepo.findByUsername(TEST_101_USERNAME).orElseThrow(assertionError("Not found"));
    ScimUser scimUser2 = userConverter.dtoFromEntity(account2);

    members.add(scimUser);

    IamGroup group =
        iamGroupRepo.findByName(TEST_001_GROUPNAME).orElseThrow(assertionError("Not found"));
    ScimGroup scimGroup = groupConverter.dtoFromEntity(group);

    savePendingGroupRequest(scimUser.getUserName(), scimGroup.getDisplayName(),
        Date.from(clock.instant()));
    savePendingGroupRequest(scimUser2.getUserName(), scimGroup.getDisplayName(),
        Date.from(clock.instant()));

    assertThat(
        groupRequestRepo.findByUsernameAndGroup(TEST_100_USERNAME, TEST_001_GROUPNAME).isEmpty(),
        is(false));

    assertThat(
        groupRequestRepo.findByUsernameAndGroup(TEST_101_USERNAME, TEST_001_GROUPNAME).isEmpty(),
        is(false));

    ScimGroupPatchRequest patchReq = getPatchAddUsersRequest(members);

    performScimWithToken(patch(scimGroup.getMeta().getLocation()).contentType(SCIM_CONTENT_TYPE)
      .content(objectMapper.writeValueAsString(patchReq)), scimAccessToken)
        .andExpect(status().isNoContent());

    assertIsGroupMember(scimUser, scimGroup);

    assertThat(
        groupRequestRepo.findByUsernameAndGroup(TEST_100_USERNAME, TEST_001_GROUPNAME).isEmpty(),
        is(true));

    assertThat(
        groupRequestRepo.findByUsernameAndGroup(TEST_101_USERNAME, TEST_001_GROUPNAME).isEmpty(),
        is(false));
  }

  @Test
  void testGroupPatchAddMembers() throws Exception {

    List<ScimUser> members = new ArrayList<>();
    members.add(lennon);
    members.add(lincoln);

    ScimGroupPatchRequest patchAddReq = getPatchAddUsersRequest(members);

    performScimWithToken(patch(engineers.getMeta().getLocation()).contentType(SCIM_CONTENT_TYPE)
      .content(objectMapper.writeValueAsString(patchAddReq)), scimAccessToken)
        .andExpect(status().isNoContent());

    performScimWithToken(get(engineers.getMeta().getLocation()).contentType(SCIM_CONTENT_TYPE),
        scimAccessToken).andExpect(status().isOk())
          .andExpect(jsonPath("$.id", equalTo(engineers.getId())))
          .andExpect(jsonPath("$.displayName", equalTo(engineers.getDisplayName())));

    assertIsGroupMember(lennon, engineers);
    assertIsGroupMember(lincoln, engineers);
  }

  @Test
  void testGroupPatchAddMembersWithFakeUser() throws Exception {

    List<ScimUser> members = new ArrayList<>();
    ScimUser ringo = addTestUser("ringo", "mail@domain.com", "Ringo", "Star");

    members.add(lennon);
    members.add(ringo);

    performScimWithToken(delete(ringo.getMeta().getLocation()), scimAccessToken)
      .andExpect(status().isNoContent());

    ScimGroupPatchRequest patchAddReq = getPatchAddUsersRequest(members);

    performScimWithToken(patch(engineers.getMeta().getLocation()).contentType(SCIM_CONTENT_TYPE)
      .content(objectMapper.writeValueAsString(patchAddReq)), scimAccessToken)
        .andExpect(status().isBadRequest());

    performScimWithToken(get(engineers.getMeta().getLocation()).contentType(SCIM_CONTENT_TYPE),
        scimAccessToken).andExpect(status().isOk())
          .andExpect(jsonPath("$.id", equalTo(engineers.getId())))
          .andExpect(jsonPath("$.displayName", equalTo(engineers.getDisplayName())))
          .andExpect(jsonPath("$.members").doesNotExist());
  }

  @Test
  void testGroupPatchAddEmptyMembersList() throws Exception {

    ScimGroupPatchRequest patchAddReq = getPatchAddUsersRequest(new ArrayList<ScimUser>());

    performScimWithToken(patch(engineers.getMeta().getLocation()).contentType(SCIM_CONTENT_TYPE)
      .content(objectMapper.writeValueAsString(patchAddReq)), scimAccessToken)
        .andExpect(status().isNoContent());

    performScimWithToken(get(engineers.getMeta().getLocation()).contentType(SCIM_CONTENT_TYPE),
        scimAccessToken).andExpect(status().isOk())
          .andExpect(jsonPath("$.id", equalTo(engineers.getId())))
          .andExpect(jsonPath("$.displayName", equalTo(engineers.getDisplayName())))
          .andExpect(jsonPath("$.members").doesNotExist());
  }
}
