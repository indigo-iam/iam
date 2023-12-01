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
package it.infn.mw.iam.test.api.account.find;

import static it.infn.mw.iam.api.account.find.FindAccountController.FIND_BY_EMAIL_RESOURCE;
import static it.infn.mw.iam.api.account.find.FindAccountController.FIND_BY_GROUP_RESOURCE;
import static it.infn.mw.iam.api.account.find.FindAccountController.FIND_BY_LABEL_RESOURCE;
import static it.infn.mw.iam.api.account.find.FindAccountController.FIND_BY_USERNAME_RESOURCE;
import static it.infn.mw.iam.api.account.find.FindAccountController.FIND_NOT_IN_GROUP_RESOURCE;
import static org.hamcrest.CoreMatchers.allOf;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
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
import it.infn.mw.iam.persistence.model.IamLabel;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamGroupRepository;
import it.infn.mw.iam.test.api.TestSupport;
import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@WithMockUser(username = "admin", roles = "ADMIN")
public class FindAccountIntegrationTests extends TestSupport {

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private IamGroupRepository groupRepo;

  @Autowired
  private IamGroupService groupService;

  @Autowired
  private IamAccountService accountService;

  @Autowired
  private MockMvc mvc;

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

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
    mvc.perform(get(FIND_BY_EMAIL_RESOURCE).param("email", "test@example")).andExpect(UNAUTHORIZED);
    mvc.perform(get(FIND_BY_USERNAME_RESOURCE).param("username", "test")).andExpect(UNAUTHORIZED);
    mvc.perform(get(FIND_BY_GROUP_RESOURCE, TEST_001_GROUP_UUID)).andExpect(UNAUTHORIZED);
    mvc.perform(get(FIND_NOT_IN_GROUP_RESOURCE, TEST_001_GROUP_UUID)).andExpect(UNAUTHORIZED);

  }

  @Test
  @WithMockUser(username = "test", roles = "USER")
  public void findingRequiresAdminUser() throws Exception {

    mvc.perform(get(FIND_BY_LABEL_RESOURCE).param("name", "test").param("value", "test"))
      .andExpect(FORBIDDEN);

    mvc.perform(get(FIND_BY_EMAIL_RESOURCE).param("email", "test@example")).andExpect(FORBIDDEN);
    mvc.perform(get(FIND_BY_USERNAME_RESOURCE).param("username", "test")).andExpect(FORBIDDEN);
    mvc.perform(get(FIND_BY_GROUP_RESOURCE, TEST_001_GROUP_UUID)).andExpect(FORBIDDEN);
    mvc.perform(get(FIND_NOT_IN_GROUP_RESOURCE, TEST_001_GROUP_UUID)).andExpect(FORBIDDEN);

  }

  @Test
  public void findByLabelWorks() throws Exception {

    IamAccount testAccount = accountRepo.findByUsername(TEST_USER)
      .orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));

    mvc.perform(get(FIND_BY_LABEL_RESOURCE).param("name", "test").param("value", "test"))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults", is(0)))
      .andExpect(jsonPath("$.Resources", emptyIterable()));

    IamLabel testLabel = IamLabel.builder().name("test").build();
    accountService.setLabel(testAccount, testLabel);

    mvc.perform(get(FIND_BY_LABEL_RESOURCE).param("name", "test").param("value", "test"))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults", is(0)))
      .andExpect(jsonPath("$.Resources", emptyIterable()));

    testLabel = IamLabel.builder().name("test").value("test").build();
    testAccount.getLabels().add(testLabel);
    accountService.setLabel(testAccount, testLabel);

    mvc.perform(get(FIND_BY_LABEL_RESOURCE).param("name", "test").param("value", "test"))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults", is(1)))
      .andExpect(jsonPath("$.Resources[0].id", is(testAccount.getUuid())));

    mvc.perform(get(FIND_BY_LABEL_RESOURCE).param("name", "toast").param("value", "test"))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults", is(0)))
      .andExpect(jsonPath("$.Resources", emptyIterable()));
  }

  @Test
  public void findByEmailWorks() throws Exception {

    IamAccount testAccount = accountRepo.findByUsername(TEST_USER)
      .orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));

    String email = testAccount.getUserInfo().getEmail();

    mvc.perform(get(FIND_BY_EMAIL_RESOURCE).param("email", email))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults", is(1)))
      .andExpect(jsonPath("$.Resources[0].id", is(testAccount.getUuid())));

    mvc.perform(get(FIND_BY_EMAIL_RESOURCE).param("email", "not_found@example"))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults").doesNotExist())
      .andExpect(jsonPath("$.Resources", emptyIterable()));

  }

  @Test
  public void findByUsernameWorks() throws Exception {

    IamAccount testAccount = accountRepo.findByUsername(TEST_USER)
      .orElseThrow(assertionError(EXPECTED_ACCOUNT_NOT_FOUND));

    mvc.perform(get(FIND_BY_USERNAME_RESOURCE).param("username", testAccount.getUsername()))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults", is(1)))
      .andExpect(jsonPath("$.Resources[0].id", is(testAccount.getUuid())));

    mvc.perform(get(FIND_BY_USERNAME_RESOURCE).param("username", "unknown_username"))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults").doesNotExist())
      .andExpect(jsonPath("$.Resources", emptyIterable()));

  }

  @Test
  public void findByGroupWorks() throws Exception {

    IamAccount testAccount = accountRepo.findByUsername(TEST_USER)
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

    mvc.perform(get(FIND_BY_GROUP_RESOURCE, rootGroup.getUuid()))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults", is(0)))
      .andExpect(jsonPath("$.Resources", emptyIterable()));

    accountService.addToGroup(testAccount, rootGroup);

    mvc.perform(get(FIND_BY_GROUP_RESOURCE, rootGroup.getUuid()))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults", is(1)))
      .andExpect(jsonPath("$.Resources[0].id", is(testAccount.getUuid())));

    mvc.perform(get(FIND_BY_GROUP_RESOURCE, rootGroup.getUuid()).param("filter", ""))
      .andExpect(BAD_REQUEST)
      .andExpect(jsonPath("$.detail", allOf(containsString("Invalid find account request"),
          containsString("Please provide a non-blank"), containsString("between 2 and 64"))));

    mvc.perform(get(FIND_BY_GROUP_RESOURCE, rootGroup.getUuid()).param("filter", "  "))
      .andExpect(BAD_REQUEST)
      .andExpect(jsonPath("$.detail", allOf(containsString("Invalid find account request"),
          containsString("Please provide a non-blank"), not(containsString("between 2 and 64")))));

    mvc.perform(get(FIND_BY_GROUP_RESOURCE, rootGroup.getUuid()).param("filter", "no_match"))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults", is(0)))
      .andExpect(jsonPath("$.Resources", emptyIterable()));

    mvc.perform(get(FIND_BY_GROUP_RESOURCE, rootGroup.getUuid()).param("filter", "est"))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults", is(1)))
      .andExpect(jsonPath("$.Resources[0].id", is(testAccount.getUuid())));
  }

  @Test
  public void findNotInGroupWorks() throws Exception {
    IamAccount adminAccount =
        accountRepo.findByUsername(ADMIN_USER)
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

    final long allUserCount = accountRepo.count();

    mvc.perform(get(FIND_NOT_IN_GROUP_RESOURCE, rootGroup.getUuid()).param("count", "10"))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults", is((int) allUserCount)));

    mvc.perform(get(FIND_NOT_IN_GROUP_RESOURCE, rootGroup.getUuid()).param("filter", "admin"))
      .andExpect(OK)
      .andExpect(jsonPath("$.totalResults", is(2)))
      .andExpect(jsonPath("$.Resources[0].id", is(adminAccount.getUuid())))
      .andExpect(jsonPath("$.Resources[1].id", is("bffc67b7-47fe-410c-a6a0-cf00173a8fbb")));
  }

}
