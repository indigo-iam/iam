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
package it.infn.mw.iam.core.oauth.profile.iam;

import java.util.Set;

import org.springframework.security.oauth2.core.oidc.OidcScopes;

import com.google.common.collect.Sets;

import it.infn.mw.iam.core.oauth.profile.common.BaseScopeClaimTranslationService;

public class IamScopeClaimTranslationService extends BaseScopeClaimTranslationService {

  @Override
  public Set<String> getClaimsForScope(String scope) {

    switch (scope) {
      case OidcScopes.PROFILE:
        Set<String> claims = super.getClaimsForScope(scope);
        claims.add(IamExtraClaimNames.AFFILIATION);
        claims.add(IamExtraClaimNames.EXTERNAL_AUTHN);
        claims.add(IamExtraClaimNames.GROUPS);
        claims.add(IamExtraClaimNames.LAST_LOGIN_AT);
        claims.add(IamExtraClaimNames.ORGANISATION_NAME);
        return claims;
      case IamOidcScopes.ATTR:
        return Sets.newHashSet(IamExtraClaimNames.ATTR);
      case IamOidcScopes.SSH_KEYS:
        return Sets.newHashSet(IamExtraClaimNames.SSH_KEYS);
      default:
        return super.getClaimsForScope(scope);
    }
  }

}
