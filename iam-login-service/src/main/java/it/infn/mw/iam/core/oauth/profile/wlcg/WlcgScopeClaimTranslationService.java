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

import java.util.Set;

import org.springframework.security.oauth2.core.oidc.OidcScopes;

import com.google.common.collect.Sets;

import it.infn.mw.iam.core.oauth.profile.iam.IamExtraClaimNames;
import it.infn.mw.iam.core.oauth.profile.iam.IamScopeClaimTranslationService;

public class WlcgScopeClaimTranslationService extends IamScopeClaimTranslationService {

  @Override
  public Set<String> getClaimsForScope(String scope) {

    switch (scope) {
      case WlcgOidcScopes.WLCG:
        return Sets.newHashSet(WlcgExtraClaimNames.WLCG_GROUPS, WlcgExtraClaimNames.WLCG_VER,
            WlcgExtraClaimNames.EDUPERSON_ASSURANCE, WlcgExtraClaimNames.AUTH_TIME);
      case OidcScopes.PROFILE:
        Set<String> profileClaims = super.getClaimsForScope(scope);
        profileClaims.add(WlcgExtraClaimNames.WLCG_VER);
        profileClaims.add(WlcgExtraClaimNames.WLCG_GROUPS);
        profileClaims.add(WlcgExtraClaimNames.EDUPERSON_ASSURANCE);
        profileClaims.add(WlcgExtraClaimNames.AUTH_TIME);
        profileClaims.remove(IamExtraClaimNames.GROUPS);
        return profileClaims;
      default:
        return super.getClaimsForScope(scope);
    }
  }

}
