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
package it.infn.mw.iam.test.util;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.client.service.DefaultClientService;
import it.infn.mw.iam.api.requests.GroupRequestUtils;
import it.infn.mw.iam.api.requests.model.GroupRequestDto;
import it.infn.mw.iam.core.expression.IamSecurityExpressionMethods;
import it.infn.mw.iam.core.userinfo.OAuth2AuthenticationScopeResolver;
import it.infn.mw.iam.persistence.repository.IamGroupRequestRepository;
import it.infn.mw.iam.test.api.requests.GroupRequestsTestUtils;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
public class IamSecurityExpressionsTests extends GroupRequestsTestUtils {

  @Autowired
  private AccountUtils accountUtils;

  @Autowired
  private DefaultClientService clientService;

  @Autowired
  private GroupRequestUtils groupRequestUtils;

  @Autowired
  private OAuth2AuthenticationScopeResolver scopeResolver;

  @Autowired
  private IamGroupRequestRepository repo;

  @After
  public void destroy() {
    repo.deleteAll();
  }

  private IamSecurityExpressionMethods getMethods() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    return new IamSecurityExpressionMethods(authentication, accountUtils, clientService,
        groupRequestUtils, scopeResolver);
  }

  @Test
  @WithMockUser(roles = {"ADMIN", "USER"}, username = TEST_ADMIN)
  public void testIsAdmin() {
    assertTrue(getMethods().isAdmin());
    assertTrue(getMethods().isUser(TEST_ADMIN_UUID));
    assertFalse(getMethods().isUser(TEST_USERUUID));
    GroupRequestDto request = savePendingGroupRequest(TEST_USERNAME, TEST_001_GROUPNAME);
    assertTrue(getMethods().canAccessGroupRequest(request.getUuid()));
    assertTrue(getMethods().canManageGroupRequest(request.getUuid()));
    assertTrue(getMethods().userCanDeleteGroupRequest(request.getUuid()));
  }

  @Test
  @WithMockUser(roles = {"USER"}, username = TEST_USERNAME)
  public void testIsNotAdmin() {
    assertFalse(getMethods().isAdmin());
    assertTrue(getMethods().isUser(TEST_USERUUID));
    assertFalse(getMethods().isUser(TEST_ADMIN_UUID));
    GroupRequestDto request = savePendingGroupRequest(TEST_USERNAME, TEST_001_GROUPNAME);
    assertTrue(getMethods().canAccessGroupRequest(request.getUuid()));
    assertFalse(getMethods().canManageGroupRequest(request.getUuid()));
    assertTrue(getMethods().userCanDeleteGroupRequest(request.getUuid()));
    GroupRequestDto approved = saveApprovedGroupRequest(TEST_USERNAME, TEST_001_GROUPNAME);
    assertTrue(getMethods().canAccessGroupRequest(approved.getUuid()));
    assertFalse(getMethods().canManageGroupRequest(approved.getUuid()));
    assertFalse(getMethods().userCanDeleteGroupRequest(approved.getUuid()));
    GroupRequestDto notMine = savePendingGroupRequest(TEST_100_USERNAME, TEST_001_GROUPNAME);
    assertFalse(getMethods().canAccessGroupRequest(notMine.getUuid()));
    assertFalse(getMethods().canManageGroupRequest(notMine.getUuid()));
    assertFalse(getMethods().userCanDeleteGroupRequest(notMine.getUuid()));
  }
}
