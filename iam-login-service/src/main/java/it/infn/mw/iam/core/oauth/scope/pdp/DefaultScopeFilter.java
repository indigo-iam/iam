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
package it.infn.mw.iam.core.oauth.scope.pdp;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.persistence.model.AuthenticationHolderEntity;
import it.infn.mw.iam.persistence.model.IamAccount;

@Component
@SuppressWarnings("deprecation")
public class DefaultScopeFilter implements ScopeFilter {
  public static final Logger LOG = LoggerFactory.getLogger(DefaultScopeFilter.class);
  public static final Set<String> ADMIN_SCOPES = Set.of("iam:admin.read", "iam:admin.write", "scim:read", "scim:write");
  private static final Set<String> EXCLUDED_SCOPES = Set.of("openid");

  private final IamProperties config;
  private final AccountUtils accountUtils;
  private final ScopePolicyEngine policyEngine;

  public DefaultScopeFilter(IamProperties config, AccountUtils accountUtils, ScopePolicyEngine policyEngine) {
    this.config = config;
    this.accountUtils = accountUtils;
    this.policyEngine = policyEngine;
  }

  @Override
  public Set<String> filterScopes(Set<String> requestedScopes, Authentication authn) {
    Optional<IamAccount> account = accountUtils.getAuthenticatedUserAccount(authn);
    if (account.isEmpty()) {
      return requestedScopes;
    }
    return filterScopes(requestedScopes, account.get());
  }

  @Override
  public Set<String> filterScopes(Set<String> requestedScopes, IamAccount account) {
    Set<String> filteredScopes = new HashSet<>();
    filteredScopes.addAll(requestedScopes);

    filteredScopes.retainAll(adminPolicies(requestedScopes, account));
    if (config.isEnableScopeAuthz()) {
      filteredScopes.retainAll(policyEngine.apply(filteredScopes, account));
    }
    filteredScopes.addAll(excludedScopes(requestedScopes));
    return filteredScopes;
  }

  private Set<String> excludedScopes(Set<String> requestedScopes) {
    return EXCLUDED_SCOPES.stream()
        .distinct()
        .filter(requestedScopes::contains)
        .collect(Collectors.toSet());
  }

  private Set<String> adminPolicies(Set<String> requestedScopes, IamAccount account) {
    if (!accountUtils.isAdmin(account)) {
      return requestedScopes.stream()
          .filter(s -> !ADMIN_SCOPES.contains(s))
          .collect(Collectors.toSet());
    }
    return requestedScopes;
  }

  public AuthenticationHolderEntity filterScopes(AuthenticationHolderEntity authHolder) {
    authHolder.setScope(filterScopes(authHolder.getScope(), authHolder.getAuthentication()));
    return authHolder;
  }

  public OAuth2Authentication filterScopes(OAuth2Authentication authn) {
    OAuth2Request oldRequest = authn.getOAuth2Request();
    OAuth2Request updatedRequest = new OAuth2Request(oldRequest.getRequestParameters(), oldRequest.getClientId(),
        oldRequest.getAuthorities(), oldRequest.isApproved(), filterScopes(oldRequest.getScope(), authn),
        oldRequest.getResourceIds(), oldRequest.getRedirectUri(), oldRequest.getResponseTypes(),
        oldRequest.getExtensions());
    return new OAuth2Authentication(updatedRequest, authn.getUserAuthentication());
  }
}
