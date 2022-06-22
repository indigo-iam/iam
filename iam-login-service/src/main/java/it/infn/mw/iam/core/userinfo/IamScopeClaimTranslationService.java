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

import static it.infn.mw.iam.core.userinfo.UserInfoClaim.ADDRESS;
import static it.infn.mw.iam.core.userinfo.UserInfoClaim.ATTR;
import static it.infn.mw.iam.core.userinfo.UserInfoClaim.BIRTHDATE;
import static it.infn.mw.iam.core.userinfo.UserInfoClaim.EDUPERSON_ENTITLEMENT;
import static it.infn.mw.iam.core.userinfo.UserInfoClaim.EDUPERSON_SCOPED_AFFILIATION;
import static it.infn.mw.iam.core.userinfo.UserInfoClaim.EMAIL;
import static it.infn.mw.iam.core.userinfo.UserInfoClaim.EMAIL_VERIFIED;
import static it.infn.mw.iam.core.userinfo.UserInfoClaim.EXTERNAL_AUTHN;
import static it.infn.mw.iam.core.userinfo.UserInfoClaim.FAMILY_NAME;
import static it.infn.mw.iam.core.userinfo.UserInfoClaim.GENDER;
import static it.infn.mw.iam.core.userinfo.UserInfoClaim.GIVEN_NAME;
import static it.infn.mw.iam.core.userinfo.UserInfoClaim.GROUPS;
import static it.infn.mw.iam.core.userinfo.UserInfoClaim.LOCALE;
import static it.infn.mw.iam.core.userinfo.UserInfoClaim.MIDDLE_NAME;
import static it.infn.mw.iam.core.userinfo.UserInfoClaim.NAME;
import static it.infn.mw.iam.core.userinfo.UserInfoClaim.NICKNAME;
import static it.infn.mw.iam.core.userinfo.UserInfoClaim.ORGANISATION_NAME;
import static it.infn.mw.iam.core.userinfo.UserInfoClaim.PHONE_NUMBER;
import static it.infn.mw.iam.core.userinfo.UserInfoClaim.PHONE_NUMBER_VERIFIED;
import static it.infn.mw.iam.core.userinfo.UserInfoClaim.PICTURE;
import static it.infn.mw.iam.core.userinfo.UserInfoClaim.PREFERRED_USERNAME;
import static it.infn.mw.iam.core.userinfo.UserInfoClaim.PROFILE;
import static it.infn.mw.iam.core.userinfo.UserInfoClaim.SSH_KEYS;
import static it.infn.mw.iam.core.userinfo.UserInfoClaim.SUB;
import static it.infn.mw.iam.core.userinfo.UserInfoClaim.UPDATED_AT;
import static it.infn.mw.iam.core.userinfo.UserInfoClaim.WEBSITE;
import static it.infn.mw.iam.core.userinfo.UserInfoClaim.WLCG_GROUPS;
import static it.infn.mw.iam.core.userinfo.UserInfoClaim.ZONEINFO;

import java.util.EnumSet;
import java.util.HashSet;
import java.util.Set;

import org.mitre.openid.connect.service.ScopeClaimTranslationService;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.SetMultimap;
import com.google.common.collect.Sets;

@Service
@Primary
public class IamScopeClaimTranslationService implements ScopeClaimTranslationService {

  private SetMultimap<String, String> scopesToClaims = HashMultimap.create();

  public static final String OPENID_SCOPE = "openid";
  public static final String PROFILE_SCOPE = "profile";
  public static final String EMAIL_SCOPE = "email";
  public static final String PHONE_SCOPE = "phone";
  public static final String ADDRESS_SCOPE = "address";
  public static final String EDUPERSON_SCOPED_AFFILIATION_SCOPE = "eduperson_scoped_affiliation";
  public static final String EDUPERSON_ENTITLEMENT_SCOPE = "eduperson_entitlement";
  public static final String ATTR_SCOPE = "attr";
  public static final String SSH_KEYS_SCOPE = "ssh-keys";
  public static final String WLCG_GROUPS_SCOPE = "wlcg.groups";

  protected static final Set<UserInfoClaim> PROFILE_CLAIMS = EnumSet.of(NAME, PREFERRED_USERNAME,
      GIVEN_NAME, FAMILY_NAME, MIDDLE_NAME, NICKNAME, PROFILE, PICTURE, WEBSITE, GENDER, ZONEINFO,
      LOCALE, UPDATED_AT, BIRTHDATE, ORGANISATION_NAME, GROUPS, EXTERNAL_AUTHN);

  protected static final Set<UserInfoClaim> EMAIL_CLAIMS = EnumSet.of(EMAIL, EMAIL_VERIFIED);

  protected static final Set<UserInfoClaim> PHONE_CLAIMS =
      EnumSet.of(PHONE_NUMBER, PHONE_NUMBER_VERIFIED);

  public IamScopeClaimTranslationService() {
    mapScopeToClaim(OPENID_SCOPE, SUB);
    mapScopeToClaim(PROFILE_SCOPE, PROFILE_CLAIMS);
    mapScopeToClaim(EMAIL_SCOPE, EMAIL_CLAIMS);
    mapScopeToClaim(PHONE_SCOPE, PHONE_CLAIMS);
    mapScopeToClaim(ADDRESS_SCOPE, ADDRESS);
    mapScopeToClaim(EDUPERSON_SCOPED_AFFILIATION_SCOPE, EDUPERSON_SCOPED_AFFILIATION);
    mapScopeToClaim(EDUPERSON_ENTITLEMENT_SCOPE, EDUPERSON_ENTITLEMENT);
    mapScopeToClaim(ATTR_SCOPE, ATTR);
    mapScopeToClaim(SSH_KEYS_SCOPE, SSH_KEYS);
    mapScopeToClaim(WLCG_GROUPS_SCOPE, WLCG_GROUPS);
  }

  private void mapScopeToClaim(String scope, UserInfoClaim claim) {
    scopesToClaims.put(scope, claim.getClaimName());
  }

  private void mapScopeToClaim(String scope, Set<UserInfoClaim> claimSet) {
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
