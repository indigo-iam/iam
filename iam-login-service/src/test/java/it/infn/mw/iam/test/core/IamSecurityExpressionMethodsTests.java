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
package it.infn.mw.iam.test.core;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doReturn;

import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.api.requests.GroupRequestUtils;
import it.infn.mw.iam.api.requests.model.GroupRequestDto;
import it.infn.mw.iam.core.expression.IamSecurityExpressionMethods;
import it.infn.mw.iam.core.userinfo.OAuth2AuthenticationScopeResolver;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamGroupRequestRepository;
import it.infn.mw.iam.persistence.repository.client.IamAccountClientRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.test.api.requests.GroupRequestsTestUtils;

@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
@Transactional
class IamSecurityExpressionMethodsTests extends GroupRequestsTestUtils {

  static final String TEST_CLIENT_ID = "client";

  @Autowired
  GroupRequestUtils groupRequestUtils;

  @Autowired
  OAuth2AuthenticationScopeResolver scopeResolver;

  @Autowired
  IamGroupRequestRepository repo;

  @Autowired
  IamAccountClientRepository accountClientRepo;

  @Autowired
  IamAccountRepository accountRepo;

  @Autowired
  ClientService clientService;

  @Autowired
  ClientDetailsEntityService clientDetailsService;

  @Autowired
  AccountUtils accountUtils;

  @Mock
  IamClientRepository clientRepo;

  private IamSecurityExpressionMethods getMethods() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    return new IamSecurityExpressionMethods(authentication, accountUtils, groupRequestUtils,
        scopeResolver, accountClientRepo, clientRepo);
  }

  @Test
  @WithMockUser(roles = {"ADMIN", "USER"}, username = TEST_ADMIN)
  void testIsAdmin() {
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
  void testIsNotAdmin() {
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

  @Test
  @WithMockUser(roles = {"ADMIN", "USER"})
  void testIsClientOwnerNoAuthenticatedUser() {
    assertFalse(getMethods().isClientOwner("client"));
  }

  @Test
  @WithMockUser(roles = {"ADMIN", "USER"}, username = TEST_ADMIN)
  void testIsClientOwnerIsAdmin() {
    mockLinkClientToAccount(TEST_ADMIN);
    assertTrue(getMethods().isClientOwner(TEST_CLIENT_ID));
  }

  @Test
  @WithMockUser(roles = {"ADMIN", "USER"}, username = "test_200")
  void testIsClientOwnerIsUser() {
    mockLinkClientToAccount("test_200");
    assertTrue(getMethods().isClientOwner(TEST_CLIENT_ID));
  }

  @Test
  @WithMockUser(roles = {"ADMIN", "USER"}, username = TEST_ADMIN)
  void testIsClientOwnerIsNotUser() {
    mockLinkClientToAccount("test_200");
    assertFalse(getMethods().isClientOwner(TEST_CLIENT_ID));
  }

  private void mockLinkClientToAccount(String owner) {
    ClientDetailsEntity clientTest = clientDetailsService.loadClientByClientId(TEST_CLIENT_ID);
    Optional<IamAccount> account = accountRepo.findByUsername(owner);
    ClientDetailsEntity clientTestUpdate =
        clientService.linkClientToAccount(clientTest, account.get());

    doReturn(Optional.of(clientTestUpdate)).when(clientRepo).findByClientId(TEST_CLIENT_ID);
  }
}
