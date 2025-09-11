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
package it.infn.mw.iam.core.userinfo;

import java.util.HashSet;
import java.util.Set;

import org.mitre.openid.connect.service.ScopeClaimTranslationService;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.stereotype.Service;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.SetMultimap;
import com.google.common.collect.Sets;

import it.infn.mw.iam.core.oauth.profile.aarc.AarcExtraClaimNames;
import it.infn.mw.iam.core.oauth.profile.aarc.AarcOidcScopes;
import it.infn.mw.iam.core.oauth.profile.iam.IamExtraClaimNames;
import it.infn.mw.iam.core.oauth.profile.iam.IamOidcScopes;
import it.infn.mw.iam.core.oauth.profile.keycloak.KeycloakExtraClaimNames;
import it.infn.mw.iam.core.oauth.profile.wlcg.WlcgExtraClaimNames;
import it.infn.mw.iam.core.oauth.profile.wlcg.WlcgOidcScopes;

@Service
@Primary
public class IamScopeClaimTranslationService implements ScopeClaimTranslationService {

  private SetMultimap<String, String> scopesToClaims = HashMultimap.create();

  protected static final Set<String> PROFILE_CLAIMS = Set.of(StandardClaimNames.NAME,
      StandardClaimNames.PREFERRED_USERNAME, StandardClaimNames.GIVEN_NAME,
      StandardClaimNames.FAMILY_NAME, StandardClaimNames.MIDDLE_NAME, StandardClaimNames.NICKNAME,
      StandardClaimNames.PROFILE, StandardClaimNames.PICTURE, StandardClaimNames.WEBSITE,
      StandardClaimNames.GENDER, StandardClaimNames.ZONEINFO, StandardClaimNames.LOCALE,
      StandardClaimNames.UPDATED_AT, StandardClaimNames.BIRTHDATE,
      IamExtraClaimNames.ORGANISATION_NAME, IamExtraClaimNames.GROUPS,
      IamExtraClaimNames.EXTERNAL_AUTHN, KeycloakExtraClaimNames.ROLES);

  protected static final Set<String> EMAIL_CLAIMS =
      Set.of(StandardClaimNames.EMAIL, StandardClaimNames.EMAIL_VERIFIED);

  protected static final Set<String> PHONE_CLAIMS =
      Set.of(StandardClaimNames.PHONE_NUMBER, StandardClaimNames.PHONE_NUMBER_VERIFIED);

  protected static final Set<String> ALL_ENTITLEMENT_CLAIMS =
      Set.of(AarcExtraClaimNames.EDUPERSON_ENTITLEMENT, AarcExtraClaimNames.ENTITLEMENTS);

  public IamScopeClaimTranslationService() {

    mapScopeToClaim(OidcScopes.OPENID, StandardClaimNames.SUB);
    mapScopeToClaim(OidcScopes.PROFILE, PROFILE_CLAIMS);
    mapScopeToClaim(OidcScopes.EMAIL, EMAIL_CLAIMS);
    mapScopeToClaim(OidcScopes.PHONE, PHONE_CLAIMS);
    mapScopeToClaim(OidcScopes.ADDRESS, StandardClaimNames.ADDRESS);
    mapScopeToClaim(AarcOidcScopes.EDUPERSON_SCOPED_AFFILIATION,
        AarcExtraClaimNames.EDUPERSON_SCOPED_AFFILIATION);
    mapScopeToClaim(AarcOidcScopes.ENTITLEMENTS, AarcExtraClaimNames.ENTITLEMENTS);
    mapScopeToClaim(AarcOidcScopes.EDUPERSON_ENTITLEMENT, ALL_ENTITLEMENT_CLAIMS);
    mapScopeToClaim(AarcOidcScopes.EDUPERSON_ASSURANCE, AarcExtraClaimNames.EDUPERSON_ASSURANCE);
    mapScopeToClaim(AarcOidcScopes.VO_PERSON_ID, AarcExtraClaimNames.VO_PERSON_ID);
    mapScopeToClaim(IamOidcScopes.ATTR, IamExtraClaimNames.ATTR);
    mapScopeToClaim(IamOidcScopes.SSH_KEYS, IamExtraClaimNames.SSH_KEYS);
    mapScopeToClaim(WlcgOidcScopes.WLCG_GROUPS, WlcgExtraClaimNames.WLCG_GROUPS);
  }

  private void mapScopeToClaim(String scope, String claim) {

    scopesToClaims.put(scope, claim);
  }

  private void mapScopeToClaim(String scope, Set<String> claimSet) {

    claimSet.forEach(c -> mapScopeToClaim(scope, c));
  }

  @Override
  public Set<String> getClaimsForScope(String scope) {

    if (scopesToClaims.containsKey(scope)) {
      return scopesToClaims.get(scope);
    } else {
      return Sets.newHashSet();
    }
  }

  @Override
  public Set<String> getClaimsForScopeSet(Set<String> scopes) {

    Set<String> result = new HashSet<>();
    for (String scope : scopes) {
      result.addAll(getClaimsForScope(scope));
    }
    return result;
  }
}
