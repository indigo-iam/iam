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
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertThrows;
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

class DefaultScopeFilterPublicClientTests {

  private static final String PUBLIC_CLIENT_ID = "test-public-client";
  private static final String CONFIDENTIAL_CLIENT_ID = "test-confidential-client";

  private final AccountUtils accountUtils = mock(AccountUtils.class);
  private final ScopePolicyEngine policyEngine = mock(ScopePolicyEngine.class);
  private final ClientDetailsService clientDetailsService = mock(ClientDetailsService.class);
  private final IamProperties properties = new IamProperties();

  private DefaultScopeFilter scopeFilter;

  @BeforeEach
  void setup() {
    properties.getScopeAuthz().setEnabled(false);
    scopeFilter =
        new DefaultScopeFilter(properties, accountUtils, policyEngine, properties, clientDetailsService);

    when(clientDetailsService.loadClientByClientId(PUBLIC_CLIENT_ID))
      .thenReturn(clientWithAuthMethod(ClientAuthMethod.NONE));
    when(clientDetailsService.loadClientByClientId(CONFIDENTIAL_CLIENT_ID))
      .thenReturn(clientWithAuthMethod(ClientAuthMethod.SECRET_BASIC));
  }

  private ClientDetailsEntity clientWithAuthMethod(ClientAuthMethod method) {
    ClientDetailsEntity client = new ClientDetailsEntity();
    client.setTokenEndpointAuthMethod(method);
    return client;
  }

  @Test
  void publicClientRequestingAdminScopeIsRejected() {
    IamAccount admin = mock(IamAccount.class);
    when(accountUtils.isAdmin(admin)).thenReturn(true);

    Set<String> requested = Set.of("openid", "iam:admin.write");

    assertThrows(InvalidRequestException.class,
        () -> scopeFilter.filterScopes(requested, admin, PUBLIC_CLIENT_ID));
  }

  @Test
  void publicClientRequestingScimScopeIsRejected() {
    IamAccount account = mock(IamAccount.class);

    Set<String> requested = Set.of("openid", "scim:read");

    assertThrows(InvalidRequestException.class,
        () -> scopeFilter.filterScopes(requested, account, PUBLIC_CLIENT_ID));
  }

  @Test
  void publicClientRequestingNonAdminScopesIsAllowed() {
    IamAccount account = mock(IamAccount.class);

    Set<String> requested = Set.of("openid", "profile");

    Set<String> filtered = scopeFilter.filterScopes(requested, account, PUBLIC_CLIENT_ID);

    assertThat(filtered, equalTo(requested));
  }

  @Test
  void confidentialClientAdminScopeIsStillSilentlyFilteredForNonAdmin() {
    IamAccount account = mock(IamAccount.class);
    when(accountUtils.isAdmin(account)).thenReturn(false);

    Set<String> requested = Set.of("openid", "iam:admin.write");

    Set<String> filtered = scopeFilter.filterScopes(requested, account, CONFIDENTIAL_CLIENT_ID);

    assertThat(filtered, not(hasItem("iam:admin.write")));
    assertThat(filtered, hasItem("openid"));
  }

  @Test
  void confidentialClientAdminScopeIsKeptForAdmin() {
    IamAccount admin = mock(IamAccount.class);
    when(accountUtils.isAdmin(admin)).thenReturn(true);

    Set<String> requested = Set.of("openid", "iam:admin.write");

    Set<String> filtered = scopeFilter.filterScopes(requested, admin, CONFIDENTIAL_CLIENT_ID);

    assertThat(filtered, equalTo(requested));
  }
}
