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
package it.infn.mw.iam.test.oauth.scope;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anySet;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.provider.ClientDetailsService;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.scope.pdp.DefaultScopeFilter;
import it.infn.mw.iam.core.oauth.scope.pdp.ScopePolicyEngine;
import it.infn.mw.iam.persistence.model.ClientAuthMethod;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.model.IamAccount;

class DefaultScopeFilterUserManagerTests {

  static final Set<String> REQUESTED = Set.of("openid", "profile", "iam:user.read",
      "iam:user.write", "iam:admin.read", "iam:admin.write", "scim:read", "scim:write");
  static final Set<String> USER_MANAGEMENT = Set.of("iam:user.read", "iam:user.write");

  final AccountUtils accountUtils = mock(AccountUtils.class);
  final ScopePolicyEngine policyEngine = mock(ScopePolicyEngine.class);
  final ClientDetailsService clients = mock(ClientDetailsService.class);
  final IamProperties properties = new IamProperties();
  final IamAccount account = mock(IamAccount.class);

  DefaultScopeFilter scopeFilter;

  @BeforeEach
  void setup() {
    properties.getScopeAuthz().setEnabled(false);
    scopeFilter =
        new DefaultScopeFilter(properties, accountUtils, policyEngine, properties, clients);

    when(clients.loadClientByClientId("confidential"))
      .thenReturn(client(ClientAuthMethod.SECRET_BASIC));
    when(clients.loadClientByClientId("public")).thenReturn(client(ClientAuthMethod.NONE));
  }

  private ClientDetailsEntity client(ClientAuthMethod method) {
    ClientDetailsEntity client = new ClientDetailsEntity();
    client.setTokenEndpointAuthMethod(method);
    return client;
  }

  private Set<String> filtered() {
    return scopeFilter.filterScopes(REQUESTED, account, "confidential");
  }

  @Test
  void privilegedScopesDependOnTheRole() {

    assertThat(filtered(), equalTo(Set.of("openid", "profile")));

    when(accountUtils.isUserManager(account)).thenReturn(true);
    assertThat(filtered(),
        equalTo(Set.of("openid", "profile", "iam:user.read", "iam:user.write")));

    when(accountUtils.isAdmin(account)).thenReturn(true);
    assertThat(filtered(), equalTo(REQUESTED));
  }

  @Test
  void publicClientsCannotRequestTheUserManagementScopes() {

    when(accountUtils.isUserManager(account)).thenReturn(true);

    assertThrows(InvalidRequestException.class,
        () -> scopeFilter.filterScopes(USER_MANAGEMENT, account, "public"));
  }

  @Test
  void scopePoliciesNeitherRemoveNorGrantTheUserManagementScopes() {

    properties.getScopeAuthz().setEnabled(true);

    when(policyEngine.apply(anySet(), any(), anyString())).thenAnswer(i -> i.getArgument(0));
    assertThat(filtered(), equalTo(Set.of("openid", "profile")));

    when(accountUtils.isUserManager(account)).thenReturn(true);
    when(policyEngine.apply(anySet(), any(), anyString())).thenReturn(Set.of("openid"));
    assertThat(filtered(), equalTo(Set.of("openid", "iam:user.read", "iam:user.write")));
  }
}
