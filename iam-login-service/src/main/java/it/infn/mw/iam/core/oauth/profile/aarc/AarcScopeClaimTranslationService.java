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

import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;

import com.google.common.collect.Sets;

import it.infn.mw.iam.core.oauth.profile.common.BaseScopeClaimTranslationService;

public class AarcScopeClaimTranslationService extends BaseScopeClaimTranslationService {

  @SuppressWarnings("deprecation")
  @Override
  public Set<String> getClaimsForScope(String scope) {

    // @formatter:off
    switch (scope) {
      case AarcOidcScopes.AARC:
        return Sets.newHashSet(
            AarcExtraClaimNames.AARC_VER,
            AarcExtraClaimNames.EDUPERSON_ASSURANCE,
            AarcExtraClaimNames.EDUPERSON_SCOPED_AFFILIATION,
            AarcExtraClaimNames.ENTITLEMENTS,
            AarcExtraClaimNames.ORGANIZATION_NAME,
            AarcExtraClaimNames.VOPERSON_EXTERNAL_AFFILIATION,
            StandardClaimNames.NAME,
            StandardClaimNames.GIVEN_NAME,
            StandardClaimNames.FAMILY_NAME,
            StandardClaimNames.EMAIL
            );
      case AarcOidcScopes.EDUPERSON_ASSURANCE:
        return Sets.newHashSet(
            AarcExtraClaimNames.EDUPERSON_ASSURANCE
            );
      case AarcOidcScopes.ENTITLEMENTS:
        return Sets.newHashSet(
            AarcExtraClaimNames.ENTITLEMENTS
            );
      case AarcOidcScopes.VOPERSON_EXTERNAL_AFFILIATION:
        return Sets.newHashSet(
            AarcExtraClaimNames.VOPERSON_EXTERNAL_AFFILIATION
            );
      case AarcOidcScopes.EDUPERSON_SCOPED_AFFILIATION:
        return Sets.newHashSet(
            AarcExtraClaimNames.EDUPERSON_SCOPED_AFFILIATION
            );
      case AarcOidcScopes.EDUPERSON_ENTITLEMENT:
        return Sets.newHashSet(
            AarcExtraClaimNames.EDUPERSON_ENTITLEMENT,
            AarcExtraClaimNames.ENTITLEMENTS);
      case OidcScopes.PROFILE:
        return merge(scope, Sets.newHashSet(
            AarcExtraClaimNames.AARC_VER,
            AarcExtraClaimNames.VOPERSON_ID));
      default:
        return super.getClaimsForScope(scope);
    }
    // @formatter:on
  }

  protected Set<String> merge(String scope, Set<String> extraClaims) {

    Set<String> merged = super.getClaimsForScope(scope);
    merged.addAll(extraClaims);
    return merged;
  }
}
