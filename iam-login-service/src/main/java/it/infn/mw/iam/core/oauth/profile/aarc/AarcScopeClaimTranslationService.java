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
package it.infn.mw.iam.core.oauth.profile.aarc;

import java.util.Set;

import com.google.common.collect.Sets;

import it.infn.mw.iam.core.oauth.profile.common.BaseScopeClaimTranslationService;

public class AarcScopeClaimTranslationService extends BaseScopeClaimTranslationService {

  @SuppressWarnings("deprecation")
  @Override
  public Set<String> getClaimsForScope(String scope) {

    switch (scope) {
      case AarcOidcScopes.AARC:
        return Sets.newHashSet(AarcExtraClaimNames.VOPERSON_ID, AarcExtraClaimNames.ENTITLEMENTS,
            AarcExtraClaimNames.VOPERSON_SCOPED_AFFILIATION,
            AarcExtraClaimNames.VOPERSON_EXTERNAL_AFFILIATION,
            AarcExtraClaimNames.EDUPERSON_ASSURANCE);
      case AarcOidcScopes.EDUPERSON_ASSURANCE:
        return Sets.newHashSet(AarcExtraClaimNames.EDUPERSON_ASSURANCE);
      case AarcOidcScopes.ENTITLEMENTS:
        return Sets.newHashSet(AarcExtraClaimNames.ENTITLEMENTS);
      case AarcOidcScopes.VOPERSON_ID:
        return Sets.newHashSet(AarcExtraClaimNames.VOPERSON_ID);
      case AarcOidcScopes.VOPERSON_EXTERNAL_AFFILIATION:
        return Sets.newHashSet(AarcExtraClaimNames.VOPERSON_EXTERNAL_AFFILIATION);
      case AarcOidcScopes.VOPERSON_SCOPED_AFFILIATION:
        return Sets.newHashSet(AarcExtraClaimNames.VOPERSON_SCOPED_AFFILIATION);
      case AarcOidcScopes.EDUPERSON_SCOPED_AFFILIATION:
        return Sets.newHashSet(AarcExtraClaimNames.EDUPERSON_SCOPED_AFFILIATION,
            AarcExtraClaimNames.VOPERSON_SCOPED_AFFILIATION);
      case AarcOidcScopes.EDUPERSON_ENTITLEMENT:
        return Sets.newHashSet(AarcExtraClaimNames.EDUPERSON_ENTITLEMENT,
            AarcExtraClaimNames.ENTITLEMENTS);
      default:
        return super.getClaimsForScope(scope);
    }
  }

}
