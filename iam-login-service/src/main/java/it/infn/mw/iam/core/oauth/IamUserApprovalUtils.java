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
package it.infn.mw.iam.core.oauth;

import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Component;

import com.google.common.base.Joiner;
import com.google.common.collect.Sets;

import it.infn.mw.iam.core.oauth.profile.ClaimValueHelper;
import it.infn.mw.iam.core.oauth.profile.JWTProfile;
import it.infn.mw.iam.core.oauth.profile.JWTProfileResolver;
import it.infn.mw.iam.core.oauth.profile.ScopeClaimTranslationService;
import it.infn.mw.iam.core.oauth.scope.SystemScopeService;
import it.infn.mw.iam.core.stats.StatsService;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.SystemScope;

@SuppressWarnings("deprecation")
@Component
public class IamUserApprovalUtils {

  private final SystemScopeService scopeService;
  private final StatsService statsService;
  private final IamAccountService accountService;
  private final JWTProfileResolver profileResolver;

  public IamUserApprovalUtils(SystemScopeService scopeService, StatsService statsService,
      IamAccountService accountService, JWTProfileResolver profileResolver) {
    this.scopeService = scopeService;
    this.statsService = statsService;
    this.accountService = accountService;
    this.profileResolver = profileResolver;
  }

  public Set<String> sortScopes(Set<SystemScope> scopes) {

    Set<SystemScope> sortedScopes = new LinkedHashSet<>(scopes.size());
    Set<SystemScope> systemScopes = scopeService.getAll();

    systemScopes.forEach(s -> {
      if (scopes.contains(s)) {
        sortedScopes.add(s);
      }
    });

    sortedScopes.addAll(Sets.difference(scopes, systemScopes));

    return scopeService.toStrings(sortedScopes);
  }

  public Map<String, Map<String, Object>> claimsForScopes(Authentication authUser,
      Set<SystemScope> scopes) {

    JWTProfile jwtProfile = profileResolver.resolveProfile(scopeService.toStrings(scopes));
    Optional<IamAccount> account = accountService.findByUsername(authUser.getName());
    ScopeClaimTranslationService scopeClaimTranslationService =
        jwtProfile.getScopeClaimTranslationService();
    ClaimValueHelper claimValueHelper = jwtProfile.getClaimValueHelper();

    Map<String, Map<String, Object>> claimsForScopes = new HashMap<>();
    if (account.isPresent()) {
      for (SystemScope systemScope : scopes) {
        Set<String> claims = scopeClaimTranslationService.getClaimsForScope(systemScope.getValue());
        Map<String, Object> claimValues = claimValueHelper.resolveClaims(claims, authUser, account);
        claimsForScopes.put(systemScope.getValue(), claimValues);
      }
    }
    return claimsForScopes;
  }

  public Integer approvedSiteCount(String clientId) {

    return statsService.getCountForClientId(clientId).getApprovedSiteCount();
  }

  public Boolean isSafeClient(Integer count, Date clientCreatedAt) {

    Date lastWeek = new Date(System.currentTimeMillis() - (60 * 60 * 24 * 7 * 1000));
    return count > 1 && clientCreatedAt != null && clientCreatedAt.before(lastWeek);
  }

  public String getClientContactsAsString(Set<String> clientContacts) {

    if (clientContacts != null) {
      return Joiner.on(", ").join(clientContacts);
    }
    return "No contacts";
  }
}
