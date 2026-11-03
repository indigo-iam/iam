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
package it.infn.mw.iam.config.security;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.core.userinfo.OAuth2AuthenticationScopeResolver;

/**
 * Checks token scopes in the HTTP filter chain before MVC deserializes request bodies.
 *
 * Keep the scope resolution consistent with the controller's
 * {@code @PreAuthorize("#iam.hasScope('scim:write')")} expression.
 */
@Component("iamApiAuthorization")
@SuppressWarnings("deprecation")
public class IamApiAuthorization {

  public static final String ROLE_ADMIN = "ROLE_ADMIN";
  public static final String ROLE_USER = "ROLE_USER";
  public static final String ROLE_GM = "ROLE_GM:";

  private final OAuth2AuthenticationScopeResolver scopeResolver;
  private final AccountUtils accountUtils;

  public IamApiAuthorization(OAuth2AuthenticationScopeResolver scopeResolver,
      AccountUtils accountUtils) {
    this.scopeResolver = scopeResolver;
    this.accountUtils = accountUtils;
  }

  public boolean hasScope(Authentication authentication, String scope) {
    if (!(authentication instanceof OAuth2Authentication oauth)) {
      return false;
    }

    return scopeResolver.resolveScope(oauth).contains(scope);
  }

  /**
   * Authorizes PATCH /scim/Users/{id} before request-body deserialization.
   * Preserve the existing method security rules for scope, ownership and dashboard admin.
   */
  public boolean canPatchScimUser(Authentication authentication, HttpServletRequest request,
      String scope) {
    if (hasScope(authentication, scope)) {
      return true;
    }
    if (authentication == null) {
      return false;
    }

    String prefix = request.getContextPath() + "/scim/Users/";
    String uri = request.getRequestURI();
    if (!uri.startsWith(prefix)) {
      return false;
    }
    String userId = uri.substring(prefix.length());
    if (userId.isEmpty() || userId.contains("/")) {
      return false;
    }

    if (!(authentication instanceof OAuth2Authentication) &&
        authentication.getAuthorities().stream()
          .anyMatch(a -> a.getAuthority().contains(ROLE_ADMIN))) {
      return true;
    }

    return accountUtils.getAuthenticatedUserAccount(authentication)
      .map(account -> userId.equals(account.getUuid()))
      .orElse(false);
  }

  /**
   * Checks the group PATCH policy before Spring MVC resolves the request body.
   * Group managers may operate only on their own group; dashboard admin
   * privileges do not transfer to bearer tokens.
   */
  public boolean canPatchScimGroup(Authentication authentication, HttpServletRequest request,
      String scope) {
    if (hasScope(authentication, scope)) {
      return true;
    }
    if (authentication == null) {
      return false;
    }

    String uri = request.getRequestURI();
    String prefix = request.getContextPath() + "/scim/Groups/";
    if (!uri.startsWith(prefix)) {
      return false;
    }
    String groupId = uri.substring(prefix.length());
    if (groupId.isEmpty() || groupId.contains("/")) {
      return false;
    }

    if (!(authentication instanceof OAuth2Authentication) &&
        authentication.getAuthorities().stream()
          .anyMatch(a -> ROLE_ADMIN.equals(a.getAuthority()))) {
      return true;
    }

    String gmAuthority = ROLE_GM + groupId;
    return authentication.getAuthorities().stream()
      .anyMatch(a -> gmAuthority.equals(a.getAuthority()));
  }

  /**
   * Checks PUT /iam/group/{id} before MVC deserializes the request body.
   */
  public boolean canUpdateGroup(Authentication authentication, HttpServletRequest request,
      String scope) {
    if (hasScope(authentication, scope)) {
      return true;
    }
    if (authentication == null) {
      return false;
    }

    String prefix = request.getContextPath() + "/iam/group/";
    String uri = request.getRequestURI();
    if (!uri.startsWith(prefix)) {
      return false;
    }
    String groupId = uri.substring(prefix.length());
    if (groupId.isEmpty() || groupId.contains("/")) {
      return false;
    }

    if (!(authentication instanceof OAuth2Authentication) &&
        authentication.getAuthorities().stream()
          .anyMatch(a -> ROLE_ADMIN.equals(a.getAuthority()))) {
      return true;
    }

    String gmAuthority = ROLE_GM + groupId;
    return authentication.getAuthorities().stream()
      .anyMatch(a -> gmAuthority.equals(a.getAuthority()));
  }

  public boolean hasScopeOrUserRole(Authentication authentication, String scope) {
    if (hasScope(authentication, scope)) {
      return true;
    }
    if (authentication == null || authentication instanceof OAuth2Authentication) {
      return false;
    }
    return authentication.getAuthorities().stream()
      .anyMatch(authority -> ROLE_USER.equals(authority.getAuthority()));
  }

  public boolean hasScopeOrDashboardAdmin(Authentication authentication, String scope) {
    if (hasScope(authentication, scope)) {
      return true;
    }
    if (authentication == null || authentication instanceof OAuth2Authentication) {
      return false;
    }
    return authentication.getAuthorities().stream()
      .anyMatch(authority -> authority.getAuthority().contains(ROLE_ADMIN));
  }
}
