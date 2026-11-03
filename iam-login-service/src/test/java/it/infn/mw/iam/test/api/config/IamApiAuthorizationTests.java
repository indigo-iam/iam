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

    assertTrue(authorization.canPatchScimUser(authentication, request, "scim:write"));
    when(request.getRequestURI()).thenReturn("/scim/Users/other-id");
    assertFalse(authorization.canPatchScimUser(authentication, request, "scim:write"));
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

    assertFalse(authorization.canPatchScimUser(authentication, request, "scim:write"));
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

    assertTrue(authorization.canPatchScimGroup(authentication, request, "scim:write"));
    when(request.getRequestURI()).thenReturn("/scim/Groups/group-2");
    assertFalse(authorization.canPatchScimGroup(authentication, request, "scim:write"));
  }

  @Test
  void groupUpdateAllowsManagerOnlyForOwnGroup() {
    Authentication authentication = mock(Authentication.class);
    doReturn(List.of(new SimpleGrantedAuthority("ROLE_GM:group-1"))).when(authentication)
      .getAuthorities();
    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getContextPath()).thenReturn("");
    when(request.getRequestURI()).thenReturn("/iam/group/group-1");

    assertTrue(authorization.canUpdateGroup(authentication, request, "iam:admin.write"));
    when(request.getRequestURI()).thenReturn("/iam/group/group-2");
    assertFalse(authorization.canUpdateGroup(authentication, request, "iam:admin.write"));
    when(request.getRequestURI()).thenReturn("/iam/group/group-1/attributes");
    assertFalse(authorization.canUpdateGroup(authentication, request, "iam:admin.write"));
  }

  @Test
  void groupUpdateAllowsDashboardAdmin() {
    Authentication authentication = mock(Authentication.class);
    doReturn(List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))).when(authentication)
      .getAuthorities();
    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getContextPath()).thenReturn("");
    when(request.getRequestURI()).thenReturn("/iam/group/group-1");

    assertTrue(authorization.canUpdateGroup(authentication, request, "iam:admin.write"));
  }

  @Test
  void groupUpdateRejectsBearerWithoutScopeEvenWithAdminAuthority() {
    OAuth2Authentication authentication = mock(OAuth2Authentication.class);
    when(scopeResolver.resolveScope(authentication)).thenReturn(Set.of("scim:read"));
    doReturn(List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))).when(authentication)
      .getAuthorities();
    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getContextPath()).thenReturn("");
    when(request.getRequestURI()).thenReturn("/iam/group/group-1");

    assertFalse(authorization.canUpdateGroup(authentication, request, "iam:admin.write"));
  }

  @Test
  void groupUpdateAllowsBearerWithAdminWriteScope() {
    OAuth2Authentication authentication = mock(OAuth2Authentication.class);
    when(scopeResolver.resolveScope(authentication)).thenReturn(Set.of("iam:admin.write"));
    HttpServletRequest request = mock(HttpServletRequest.class);

    assertTrue(authorization.canUpdateGroup(authentication, request, "iam:admin.write"));
  }

  @Test
  void userPatchRejectsMissingAuthentication() {
    assertFalse(authorization.canPatchScimUser(null, mock(HttpServletRequest.class), "scim:write"));
  }

  @Test
  void userPatchAllowsWriteScopeWithoutLookingUpUser() {
    OAuth2Authentication authentication = mock(OAuth2Authentication.class);
    when(scopeResolver.resolveScope(authentication)).thenReturn(Set.of("scim:write"));

    assertTrue(
        authorization.canPatchScimUser(authentication, mock(HttpServletRequest.class), "scim:write"));
    verifyNoInteractions(accountUtils);
  }

  @Test
  void userPatchAllowsDashboardAdmin() {
    Authentication authentication = mock(Authentication.class);
    doReturn(List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))).when(authentication)
      .getAuthorities();
    HttpServletRequest request = requestFor("/scim/Users/user-1");

    assertTrue(authorization.canPatchScimUser(authentication, request, "scim:write"));
  }

  @Test
  void userPatchRejectsMissingAccount() {
    Authentication authentication = mock(Authentication.class);
    HttpServletRequest request = requestFor("/scim/Users/user-1");
    when(accountUtils.getAuthenticatedUserAccount(authentication))
      .thenReturn(java.util.Optional.empty());

    assertFalse(authorization.canPatchScimUser(authentication, request, "scim:write"));
  }

  @Test
  void userPatchRejectsInvalidPaths() {
    Authentication authentication = mock(Authentication.class);
    for (String path : List.of("/iam/group/user-1", "/scim/Users/",
        "/scim/Users/user-1/attributes")) {
      assertFalse(authorization.canPatchScimUser(authentication, requestFor(path), "scim:write"));
    }
    verifyNoInteractions(accountUtils);
  }

  @Test
  void groupPatchRejectsMissingAuthentication() {
    assertFalse(authorization.canPatchScimGroup(null, mock(HttpServletRequest.class), "scim:write"));
  }

  @Test
  void groupPatchAllowsWriteScope() {
    OAuth2Authentication authentication = mock(OAuth2Authentication.class);
    when(scopeResolver.resolveScope(authentication)).thenReturn(Set.of("scim:write"));

    assertTrue(
        authorization.canPatchScimGroup(authentication, mock(HttpServletRequest.class), "scim:write"));
  }

  @Test
  void groupPatchAllowsDashboardAdmin() {
    Authentication authentication = mock(Authentication.class);
    doReturn(List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))).when(authentication)
      .getAuthorities();

    assertTrue(authorization.canPatchScimGroup(authentication, requestFor("/scim/Groups/group-1"),
        "scim:write"));
  }

  @Test
  void groupPatchRejectsBearerAdminWithoutScope() {
    OAuth2Authentication authentication = mock(OAuth2Authentication.class);
    when(scopeResolver.resolveScope(authentication)).thenReturn(Set.of("scim:read"));
    doReturn(List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))).when(authentication)
      .getAuthorities();

    assertFalse(authorization.canPatchScimGroup(authentication, requestFor("/scim/Groups/group-1"),
        "scim:write"));
  }

  @Test
  void groupPatchRejectsInvalidPaths() {
    Authentication authentication = mock(Authentication.class);
    for (String path : List.of("/iam/group/group-1", "/scim/Groups/",
        "/scim/Groups/group-1/attributes")) {
      assertFalse(authorization.canPatchScimGroup(authentication, requestFor(path), "scim:write"));
    }
  }

  @Test
  void groupUpdateRejectsMissingAuthentication() {
    assertFalse(
        authorization.canUpdateGroup(null, mock(HttpServletRequest.class), "iam:admin.write"));
  }

  @Test
  void groupUpdateRejectsInvalidPaths() {
    Authentication authentication = mock(Authentication.class);
    for (String path : List.of("/scim/Groups/group-1", "/iam/group/",
        "/iam/group/group-1/attributes")) {
      assertFalse(
          authorization.canUpdateGroup(authentication, requestFor(path), "iam:admin.write"));
    }
  }

  @Test
  void scopeOrUserRoleChecksSessionAndBearerSeparately() {
    Authentication user = authenticationWithRole("ROLE_USER");
    Authentication other = authenticationWithRole("ROLE_OTHER");
    assertTrue(authorization.hasScopeOrUserRole(user, "scim:write"));
    assertFalse(authorization.hasScopeOrUserRole(other, "scim:write"));
    assertFalse(authorization.hasScopeOrUserRole(null, "scim:write"));

    OAuth2Authentication bearer = mock(OAuth2Authentication.class);
    when(scopeResolver.resolveScope(bearer)).thenReturn(Set.of("scim:read"));
    doReturn(List.of(new SimpleGrantedAuthority("ROLE_USER"))).when(bearer).getAuthorities();
    assertFalse(authorization.hasScopeOrUserRole(bearer, "scim:write"));
    when(scopeResolver.resolveScope(bearer)).thenReturn(Set.of("scim:write"));
    assertTrue(authorization.hasScopeOrUserRole(bearer, "scim:write"));
  }

  @Test
  void scopeOrDashboardAdminChecksSessionAndBearerSeparately() {
    Authentication admin = authenticationWithRole("ROLE_ADMIN");
    Authentication other = authenticationWithRole("ROLE_USER");
    assertTrue(authorization.hasScopeOrDashboardAdmin(admin, "iam:admin.write"));
    assertFalse(authorization.hasScopeOrDashboardAdmin(other, "iam:admin.write"));
    assertFalse(authorization.hasScopeOrDashboardAdmin(null, "iam:admin.write"));

    OAuth2Authentication bearer = mock(OAuth2Authentication.class);
    when(scopeResolver.resolveScope(bearer)).thenReturn(Set.of("scim:read"));
    doReturn(List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))).when(bearer).getAuthorities();
    assertFalse(authorization.hasScopeOrDashboardAdmin(bearer, "iam:admin.write"));
    when(scopeResolver.resolveScope(bearer)).thenReturn(Set.of("iam:admin.write"));
    assertTrue(authorization.hasScopeOrDashboardAdmin(bearer, "iam:admin.write"));
  }

  @Test
  void pathMatchingSupportsServletContext() {
    Authentication groupManager = authenticationWithRole("ROLE_GM:group-1");
    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getContextPath()).thenReturn("/iam-app");
    when(request.getRequestURI()).thenReturn("/iam-app/iam/group/group-1");
    assertTrue(authorization.canUpdateGroup(groupManager, request, "iam:admin.write"));
    when(request.getRequestURI()).thenReturn("/iam-app/scim/Groups/group-1");
    assertTrue(authorization.canPatchScimGroup(groupManager, request, "scim:write"));
  }

  private HttpServletRequest requestFor(String path) {
    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getContextPath()).thenReturn("");
    when(request.getRequestURI()).thenReturn(path);
    return request;
  }

  private Authentication authenticationWithRole(String role) {
    Authentication authentication = mock(Authentication.class);
    doReturn(List.of(new SimpleGrantedAuthority(role))).when(authentication).getAuthorities();
    return authentication;
  }

  @Test
  void allowsBearerTokenWithWriteScope() {
    OAuth2Authentication authentication = mock(OAuth2Authentication.class);
    when(scopeResolver.resolveScope(authentication)).thenReturn(Set.of("scim:read", "scim:write"));

    assertTrue(authorization.hasScope(authentication, "scim:write"));
  }
}
