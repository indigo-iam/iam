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
package it.infn.mw.iam.core.expression;

import static it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport.EXT_AUTHN_UNREGISTERED_USER_AUTH;

import java.util.Collection;
import java.util.Optional;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.requests.GroupRequestUtils;
import it.infn.mw.iam.authn.AbstractExternalAuthenticationToken;
import it.infn.mw.iam.core.IamGroupRequestStatus;
import it.infn.mw.iam.core.userinfo.OAuth2AuthenticationScopeResolver;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamGroupRequest;

@SuppressWarnings("deprecation")
public class IamSecurityExpressionMethods {

  private static final String ROLE_GM = "ROLE_GM:";
  private static final String ROLE_ADMIN = "ROLE_ADMIN";

  private final Authentication authentication;
  private final AccountUtils accountUtils;
  private final GroupRequestUtils groupRequestUtils;
  private final OAuth2AuthenticationScopeResolver scopeResolver;

  public IamSecurityExpressionMethods(Authentication authentication, AccountUtils accountUtils,
      GroupRequestUtils groupRequestUtils, OAuth2AuthenticationScopeResolver scopeResolver) {
    this.authentication = authentication;
    this.accountUtils = accountUtils;
    this.groupRequestUtils = groupRequestUtils;
    this.scopeResolver = scopeResolver;
  }

  public boolean isExternallyAuthenticatedWithIssuer(String issuer) {
    if (authentication.getAuthorities().contains(EXT_AUTHN_UNREGISTERED_USER_AUTH)) {

      @SuppressWarnings("rawtypes")
      AbstractExternalAuthenticationToken token =
          (AbstractExternalAuthenticationToken) authentication;
      return token.toExernalAuthenticationRegistrationInfo().getIssuer().equals(issuer);
    }

    return false;
  }

  public enum Role {
    ROLE_ADMIN, ROLE_GM, ROLE_USER
  }

  public boolean isGroupManager(String groupUuid) {
    return authentication.getAuthorities()
      .stream()
      .anyMatch(a -> a.getAuthority().equals(ROLE_GM + groupUuid));
  }

  public boolean isAdmin() {
    return authentication.getAuthorities()
      .stream()
      .anyMatch(a -> a.getAuthority().equals(ROLE_ADMIN));
  }

  public boolean isUser(String userUuid) {
    Optional<IamAccount> account = accountUtils.getAuthenticatedUserAccount();
    return account.isPresent() && account.get().getUuid().equals(userUuid);
  }

  public boolean canManageGroupRequest(String requestId) {
    if (isAdmin()) {
      return true;
    }
    Optional<IamGroupRequest> groupRequest = groupRequestUtils.getOptionalGroupRequest(requestId);
    if (groupRequest.isEmpty()) {
      return false;
    }
    return isGroupManager(groupRequest.get().getGroup().getUuid());
  }

  public boolean canAccessGroupRequest(String requestId) {
    if (isAdmin()) {
      return true;
    }
    Optional<IamGroupRequest> groupRequest = groupRequestUtils.getOptionalGroupRequest(requestId);
    if (groupRequest.isEmpty()) {
      return false;
    }
    if (isGroupManager(groupRequest.get().getGroup().getUuid())) {
      return true;
    }
    return isUser(groupRequest.get().getAccount().getUuid());
  }

  public boolean userCanDeleteGroupRequest(String requestId) {

    if (isAdmin()) {
      return true;
    }
    Optional<IamGroupRequest> groupRequest = groupRequestUtils.getOptionalGroupRequest(requestId);
    if (groupRequest.isEmpty()) {
      return false;
    }
    if (isGroupManager(groupRequest.get().getGroup().getUuid())) {
      return true;
    }
    return isUser(groupRequest.get().getAccount().getUuid())
        && IamGroupRequestStatus.PENDING.equals(groupRequest.get().getStatus());
  }

  public boolean hasScope(String scope) {
    if (authentication instanceof OAuth2Authentication oauth) {
      return scopeResolver.resolveScope(oauth).stream().anyMatch(s -> s.equals(scope));
    }
    return false;
  }

  public boolean isRequestWithoutToken() {
    return !(authentication instanceof OAuth2Authentication);
  }

  public boolean hasAnyDashboardRole(Role... roles) {
    Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
    for (Role r : roles) {
      if (authorities.stream().anyMatch(a -> a.getAuthority().contains(r.name()))) {
        return isRequestWithoutToken();
      }
    }
    return false;
  }

  public boolean hasDashboardRole(Role role) {
    return hasAnyDashboardRole(role);
  }

  public boolean hasAdminOrGMDashboardRoleOfGroup(String gid) {
    return (hasDashboardRole(Role.ROLE_ADMIN) || isGroupManager(gid));
  }
}
