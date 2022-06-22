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
package it.infn.mw.iam.test.api.group;

import static it.infn.mw.iam.api.group.find.FindGroupController.FIND_BY_LABEL_RESOURCE;
import static it.infn.mw.iam.api.group.find.FindGroupController.FIND_BY_NAME_RESOURCE;
import static it.infn.mw.iam.api.group.find.FindGroupController.FIND_UNSUBSCRIBED_GROUPS_FOR_ACCOUNT;
import static org.apache.commons.lang3.RandomStringUtils.randomAlphabetic;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.emptyIterable;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

import java.util.function.Supplier;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import it.infn.mw.iam.core.group.IamGroupService;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamGroupRepository;
import it.infn.mw.iam.test.api.TestSupport;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@WithMockUser(username = "admin", roles = "ADMIN")
public class FindGroupTests extends TestSupport {

  @Autowired
  private MockMvc mvc;

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  @Autowired
  private IamGroupRepository groupRepo;

  @Autowired
  private IamGroupService groupService;

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private IamAccountService accountService;

  @Before
  public void setup() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @After
  public void cleanupOAuthUser() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  private Supplier<AssertionError> assertionError(String message) {
    return () -> new AssertionError(message);
  }

  @Test
  @WithAnonymousUser
  public void findingRequiresAuthenticatedUser() throws Exception {

    mvc.perform(get(FIND_BY_LABEL_RESOURCE).param("name", "test").param("value", "test"))
      .andExpect(UNAUTHORIZED);

    mvc.perform(get(FIND_BY_NAME_RESOURCE).param("name", "test")).andExpect(UNAUTHORIZED);

    mvc.perform(get(FIND_UNSUBSCRIBED_GROUPS_FOR_ACCOUNT, TEST_USER_UUID)).andExpect(UNAUTHORIZED);

  }

  @Test
  @WithMockUser(username = "test", roles = "USER")
  public void findingRequiresAdminUser() throws Exception {

    mvc.perform(get(FIND_BY_LABEL_RESOURCE).param("name", "test").param("value", "test"))
      .andExpect(FORBIDDEN);

    mvc.perform(get(FIND_BY_NAME_RESOURCE).param("name", "test")).andExpect(FORBIDDEN);

    mvc.perform(get(FIND_UNSUBSCRIBED_GROUPS_FOR_ACCOUNT, TEST_USER_UUID)).andExpect(FORBIDDEN);
  }

  @Test
  public void findByNameWorks() throws Exception {


    IamGroup group = groupRepo.findByUuid(TEST_001_GROUP_UUID)
      .orElseThrow(assertionError(EXPECTED_GROUP_NOT_FOUND));

    mvc.perform(get(FIND_BY_NAME_RESOURCE).param("name", group.getName()))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults", is(1)))
      .andExpect(jsonPath("$.Resources[0].id", is(TEST_001_GROUP_UUID)))
      .andExpect(jsonPath("$.Resources[0].members").doesNotExist());

    mvc.perform(get(FIND_BY_NAME_RESOURCE).param("name", "unknown_group"))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults").doesNotExist())
      .andExpect(jsonPath("$.Resources", emptyIterable()));

  }


  @Test
  public void findUnsubscribedGroupsWorks() throws Exception {

    IamAccount testAccount =
        accountRepo.findByUsername(TEST_USER)
          .orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));

    // Cleanup all group memberships and groups
    accountRepo.deleteAllAccountGroupMemberships();
    groupRepo.deleteAll();

    // Create group hierarchy
    IamGroup rootGroup = new IamGroup();
    rootGroup.setName("root");

    rootGroup = groupService.createGroup(rootGroup);

    IamGroup subgroup = new IamGroup();
    subgroup.setName("root/subgroup");
    subgroup.setParentGroup(rootGroup);

    subgroup = groupService.createGroup(subgroup);

    IamGroup sibling = new IamGroup();
    sibling.setName("sibling");

    sibling = groupService.createGroup(sibling);

    mvc.perform(get(FIND_UNSUBSCRIBED_GROUPS_FOR_ACCOUNT, TEST_USER_UUID))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults", is(3)))
      .andExpect(jsonPath("$.Resources[0].displayName", is("root")))
      .andExpect(jsonPath("$.Resources[1].displayName", is("root/subgroup")))
      .andExpect(jsonPath("$.Resources[2].displayName", is("sibling")));

    accountService.addToGroup(testAccount, subgroup);

    mvc.perform(get(FIND_UNSUBSCRIBED_GROUPS_FOR_ACCOUNT, TEST_USER_UUID))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults", is(1)))
      .andExpect(jsonPath("$.Resources[0].displayName", is("sibling")));

    accountService.addToGroup(testAccount, sibling);

    mvc.perform(get(FIND_UNSUBSCRIBED_GROUPS_FOR_ACCOUNT, TEST_USER_UUID))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults", is(0)))
      .andExpect(jsonPath("$.Resources", emptyIterable()));

    accountRepo.deleteAllAccountGroupMemberships();

    mvc
      .perform(get(FIND_UNSUBSCRIBED_GROUPS_FOR_ACCOUNT, TEST_USER_UUID).param("filter", "sib"))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults", is(1)))
      .andExpect(jsonPath("$.Resources[0].displayName", is("sibling")));

    mvc.perform(get(FIND_UNSUBSCRIBED_GROUPS_FOR_ACCOUNT, TEST_USER_UUID).param("filter", ""))
      .andExpect(BAD_REQUEST)
      .andExpect(jsonPath("$.status", is("400")))
      .andExpect(jsonPath("$.detail", containsString("Invalid find group request")));

    mvc.perform(get(FIND_UNSUBSCRIBED_GROUPS_FOR_ACCOUNT, TEST_USER_UUID).param("filter", "a"))
      .andExpect(BAD_REQUEST)
      .andExpect(jsonPath("$.status", is("400")))
      .andExpect(jsonPath("$.detail", containsString("Invalid find group request")));

    mvc
      .perform(get(FIND_UNSUBSCRIBED_GROUPS_FOR_ACCOUNT, TEST_USER_UUID).param("filter",
          randomAlphabetic(65)))
      .andExpect(BAD_REQUEST)
      .andExpect(jsonPath("$.status", is("400")))
      .andExpect(jsonPath("$.detail", containsString("Invalid find group request")));
      
  }

}
