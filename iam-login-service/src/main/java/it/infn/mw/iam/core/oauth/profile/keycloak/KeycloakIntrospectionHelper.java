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
package it.infn.mw.iam.core.oauth.profile.keycloak;

import static org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames.SUB;
import static org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames.USERNAME;

import java.util.Map;
import java.util.Set;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;

import it.infn.mw.iam.core.oauth.profile.common.BaseIntrospectionHelper;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;

public class KeycloakIntrospectionHelper extends BaseIntrospectionHelper {

  public KeycloakIntrospectionHelper(IamAccountService accountService) {
    super(accountService);
  }

  @Override
  public Map<String, Object> assembleIntrospectionResult(OAuth2AccessTokenEntity accessToken,
      ClientDetailsEntity authenticatedClient) {

    Map<String, Object> result =
        super.assembleIntrospectionResult(accessToken, authenticatedClient);
    addRoles(result);
    return result;
  }

  private void addRoles(Map<String, Object> claims) {

    if (claims.containsKey(USERNAME)) {
      IamAccount account = loadUserFrom(claims.get(SUB).toString()).orElseThrow(
          () -> new IllegalStateException("Token sub doesn't refer to any registered user"));

      Set<String> groups = KeycloakGroupHelper.resolveGroupNames(account.getUserInfo().getGroups());

      if (!groups.isEmpty()) {
        claims.put(KeycloakExtraClaimNames.ROLES, groups);
      }
    }
  }

}
