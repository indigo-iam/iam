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
package it.infn.mw.iam.test.api.config;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.config.security.IamApiAuthorization;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.core.userinfo.OAuth2AuthenticationScopeResolver;

@SuppressWarnings("deprecation")
class IamApiAuthorizationTests {

  private final OAuth2AuthenticationScopeResolver scopeResolver =
      mock(OAuth2AuthenticationScopeResolver.class);

  private final AccountUtils accountUtils = mock(AccountUtils.class);
  private final IamApiAuthorization authorization =
      new IamApiAuthorization(scopeResolver, accountUtils);

  @Test
  void userPatchAllowsOwnerButNotOtherUser() {
    Authentication authentication = mock(Authentication.class);
    HttpServletRequest request = mock(HttpServletRequest.class);
    IamAccount account = mock(IamAccount.class);
    when(request.getContextPath()).thenReturn("");
    when(request.getRequestURI()).thenReturn("/scim/Users/owner-id");
    when(accountUtils.getAuthenticatedUserAccount(authentication))
      .thenReturn(java.util.Optional.of(account));
    when(account.getUuid()).thenReturn("owner-id");

    assertTrue(authorization.canPatchUser(authentication, request, "scim:write"));
    when(request.getRequestURI()).thenReturn("/scim/Users/other-id");
    assertFalse(authorization.canPatchUser(authentication, request, "scim:write"));
  }

  @Test
  void userPatchRejectsClientCredentialsWithoutWriteScope() {
    OAuth2Authentication authentication = mock(OAuth2Authentication.class);
    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getContextPath()).thenReturn("");
    when(request.getRequestURI()).thenReturn("/scim/Users/owner-id");
    when(scopeResolver.resolveScope(authentication)).thenReturn(Set.of("scim:read"));
    when(accountUtils.getAuthenticatedUserAccount(authentication))
      .thenReturn(java.util.Optional.empty());

    assertFalse(authorization.canPatchUser(authentication, request, "scim:write"));
  }

  @Test
  void deniesMissingAuthentication() {
    assertFalse(authorization.hasScope(null, "scim:write"));
    verifyNoInteractions(scopeResolver);
  }

  @Test
  void deniesSessionAuthentication() {
    Authentication authentication = mock(Authentication.class);
    assertFalse(authorization.hasScope(authentication, "scim:write"));
    verifyNoInteractions(scopeResolver);
  }

  @Test
  void deniesBearerTokenWithoutWriteScope() {
    OAuth2Authentication authentication = mock(OAuth2Authentication.class);
    when(scopeResolver.resolveScope(authentication)).thenReturn(Set.of("scim:read"));

    assertFalse(authorization.hasScope(authentication, "scim:write"));
  }

  @Test
  void groupManagerCanPatchOnlyOwnGroup() {
    Authentication authentication = mock(Authentication.class);
    doReturn(List.of(new SimpleGrantedAuthority("ROLE_GM:group-1"))).when(authentication)
      .getAuthorities();
    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getRequestURI()).thenReturn("/scim/Groups/group-1");
    when(request.getContextPath()).thenReturn("");

    assertTrue(authorization.canPatchGroup(authentication, request, "scim:write"));
    when(request.getRequestURI()).thenReturn("/scim/Groups/group-2");
    assertFalse(authorization.canPatchGroup(authentication, request, "scim:write"));
  }

  @Test
  void allowsBearerTokenWithWriteScope() {
    OAuth2Authentication authentication = mock(OAuth2Authentication.class);
    when(scopeResolver.resolveScope(authentication)).thenReturn(Set.of("scim:read", "scim:write"));

    assertTrue(authorization.hasScope(authentication, "scim:write"));
  }
}
