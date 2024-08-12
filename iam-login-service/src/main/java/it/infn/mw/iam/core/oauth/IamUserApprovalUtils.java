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
import java.util.Set;

import org.mitre.oauth2.model.SystemScope;
import org.mitre.oauth2.service.SystemScopeService;
import org.mitre.openid.connect.model.UserInfo;
import org.mitre.openid.connect.service.ScopeClaimTranslationService;
import org.mitre.openid.connect.service.StatsService;
import org.mitre.openid.connect.service.UserInfoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import com.google.common.base.Joiner;
import com.google.common.collect.Sets;
import com.google.gson.JsonObject;

@Component
public class IamUserApprovalUtils {

  @Autowired
  private SystemScopeService scopeService;

  @Autowired
  private StatsService statsService;

  @Autowired
  private ScopeClaimTranslationService scopeClaimTranslationService;

  @Autowired
  private UserInfoService userInfoService;


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

  public Map<String, Map<String, String>> claimsForScopes(Authentication authUser,
      Set<SystemScope> scopes) {
    UserInfo user = userInfoService.getByUsername(authUser.getName());
    Map<String, Map<String, String>> claimsForScopes = new HashMap<>();
    if (user != null) {
      JsonObject userJson = user.toJson();

      for (SystemScope systemScope : scopes) {
        Map<String, String> claimValues = new HashMap<>();

        Set<String> claims = scopeClaimTranslationService.getClaimsForScope(systemScope.getValue());
        for (String claim : claims) {
          if (userJson.has(claim) && userJson.get(claim).isJsonPrimitive()) {
            // TODO: this skips the address claim
            claimValues.put(claim, userJson.get(claim).getAsString());
          }
        }

        claimsForScopes.put(systemScope.getValue(), claimValues);
      }
    }
    return claimsForScopes;
  }

  public Integer approvedSiteCount(String ClientId) {

    return statsService.getCountForClientId(ClientId).getApprovedSiteCount();
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
