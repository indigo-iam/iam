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

import java.time.Clock;
import java.time.Duration;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import com.google.common.base.Joiner;
import com.google.common.collect.Sets;
import com.google.gson.JsonObject;

import it.infn.mw.iam.core.oauth.consent.ConsentGrantService;
import it.infn.mw.iam.core.oauth.profile.JWTProfileResolver;
import it.infn.mw.iam.core.oauth.profile.ScopeClaimTranslationService;
import it.infn.mw.iam.core.oauth.scope.SystemScopeService;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.SystemScope;

@Component
public class IamUserApprovalUtils {

  private final Clock clock;
  private final SystemScopeService scopeService;
  private final IamAccountService accountService;
  private final JWTProfileResolver profileResolver;
  private final ConsentGrantService consentGrantService;

  public IamUserApprovalUtils(Clock clock, SystemScopeService scopeService,
      IamAccountService accountService, JWTProfileResolver profileResolver,
      ConsentGrantService consentGrantService) {
    this.clock = clock;
    this.scopeService = scopeService;
    this.accountService = accountService;
    this.profileResolver = profileResolver;
    this.consentGrantService = consentGrantService;
  }

  public Set<String> sortScopes(Set<SystemScope> scopes) {

    Set<SystemScope> sortedScopes = new TreeSet<>(Comparator.comparing(SystemScope::getValue));
    Set<SystemScope> systemScopes = scopeService.getAll();

    systemScopes.forEach(s -> {
      if (scopes.contains(s)) {
        sortedScopes.add(s);
      }
    });

    sortedScopes.addAll(Sets.difference(scopes, systemScopes));

    return scopeService.toStrings(sortedScopes);
  }

  public Map<String, Map<String, String>> claimsForScopes(Authentication authUser,
      Set<SystemScope> scopes) {

    Optional<IamAccount> account = accountService.findByUsername(authUser.getName());
    ScopeClaimTranslationService scopeClaimTranslationService =
        profileResolver.resolveProfile(scopeService.toStrings(scopes))
          .getScopeClaimTranslationService();

    Map<String, Map<String, String>> claimsForScopes = new HashMap<>();
    if (account.isPresent()) {
      JsonObject userJson = account.get().toJson();

      for (SystemScope systemScope : scopes) {
        Map<String, String> claimValues = new HashMap<>();

        Set<String> claims = scopeClaimTranslationService.getClaimsForScope(systemScope.getValue());
        for (String claim : claims) {
          if (userJson.has(claim) && userJson.get(claim).isJsonPrimitive()) {
            claimValues.put(claim, userJson.get(claim).getAsString());
          }
        }

        claimsForScopes.put(systemScope.getValue(), claimValues);
      }
    }
    return claimsForScopes;
  }

  public Integer consentGrantCount(String clientId) {

    return consentGrantService.getByClientId(clientId).size();
  }

  public Boolean isSafeClient(Integer count, Date clientCreatedAt) {

    Date lastWeek = Date.from(clock.instant().minus(Duration.ofDays(7)));
    return count > 1 && clientCreatedAt != null && clientCreatedAt.before(lastWeek);
  }

  public String getClientContactsAsString(Set<String> clientContacts) {

    if (clientContacts != null) {
      return Joiner.on(", ").join(clientContacts);
    }
    return "No contacts";
  }
}
