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

import java.util.Optional;

import org.mitre.openid.connect.service.ScopeClaimTranslationService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import it.infn.mw.iam.api.scim.converter.SshKeyConverter;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.attributes.AttributeMapHelper;
import it.infn.mw.iam.core.oauth.profile.iam.IamClaimValueHelper;
import it.infn.mw.iam.core.oauth.profile.iam.IamExtraClaimNames;
import it.infn.mw.iam.persistence.model.IamAccount;

@SuppressWarnings("deprecation")
public class KeycloakClaimValueHelper extends IamClaimValueHelper {

  public KeycloakClaimValueHelper(IamProperties properties, SshKeyConverter sshConverter,
      AttributeMapHelper attrHelper, ScopeClaimTranslationService scopeClaimTranslationService) {
    super(properties, sshConverter, attrHelper, scopeClaimTranslationService);
  }

  @Override
  public Object resolveClaim(String claimName, OAuth2Authentication auth,
      Optional<IamAccount> account) {

    if (KeycloakExtraClaimNames.ROLES.equals(claimName)) {
      if (account.isPresent()) {
        return KeycloakGroupHelper.resolveGroupNames(account.get().getUserInfo().getGroups());
      }
      return null;
    }
    if (IamExtraClaimNames.GROUPS.equals(claimName)) {
      /* remove inherited groups claim */
      return null;
    }
    return super.resolveClaim(claimName, auth, account);
  }
}
