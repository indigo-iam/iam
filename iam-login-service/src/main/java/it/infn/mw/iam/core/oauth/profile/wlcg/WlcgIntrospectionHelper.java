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
package it.infn.mw.iam.core.oauth.profile.wlcg;

import static org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames.SUB;
import static org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames.USERNAME;

import java.text.ParseException;
import java.util.Map;
import java.util.Set;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;

import it.infn.mw.iam.core.oauth.profile.common.BaseIntrospectionHelper;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;


public class WlcgIntrospectionHelper extends BaseIntrospectionHelper {

  public WlcgIntrospectionHelper(IamAccountService accountService) {
    super(accountService);
  }

  @Override
  public Map<String, Object> assembleIntrospectionResult(OAuth2AccessTokenEntity accessToken,
      ClientDetailsEntity authenticatedClient) throws ParseException {

    Map<String, Object> claims =
        super.assembleIntrospectionResult(accessToken, authenticatedClient);
    addWlcgGroups(accessToken, claims);
    return claims;
  }

  private void addWlcgGroups(OAuth2AccessTokenEntity accessToken, Map<String, Object> claims) {

    if (claims.containsKey(USERNAME)) {
      IamAccount account = loadUserFrom(claims.get(SUB).toString()).orElseThrow(
          () -> new IllegalStateException("Token sub doesn't refer to any registered user"));

      Set<String> groups = WlcgGroupHelper.resolveGroupNames(accessToken, account.getUserInfo());

      if (!groups.isEmpty()) {
        claims.put(WlcgExtraClaimNames.WLCG_GROUPS, groups);
      }
    }
  }
}
