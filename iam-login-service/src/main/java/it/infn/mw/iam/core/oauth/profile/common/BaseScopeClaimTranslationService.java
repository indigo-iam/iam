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
package it.infn.mw.iam.core.oauth.profile.common;

import java.util.Set;
import java.util.stream.Collectors;

import org.mitre.openid.connect.service.ScopeClaimTranslationService;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;

import com.google.common.collect.Sets;

public class BaseScopeClaimTranslationService implements ScopeClaimTranslationService {

  @Override
  public Set<String> getClaimsForScope(String scope) {

    switch (scope) {
      case OidcScopes.OPENID:
        return Sets.newHashSet(StandardClaimNames.SUB);
      case OidcScopes.PROFILE:
        return Sets.newHashSet(StandardClaimNames.NAME, StandardClaimNames.PREFERRED_USERNAME,
            StandardClaimNames.GIVEN_NAME, StandardClaimNames.FAMILY_NAME,
            StandardClaimNames.MIDDLE_NAME, StandardClaimNames.NICKNAME, StandardClaimNames.PROFILE,
            StandardClaimNames.PICTURE, StandardClaimNames.WEBSITE, StandardClaimNames.GENDER,
            StandardClaimNames.ZONEINFO, StandardClaimNames.LOCALE, StandardClaimNames.UPDATED_AT,
            StandardClaimNames.BIRTHDATE);
      case OidcScopes.EMAIL:
        return Sets.newHashSet(StandardClaimNames.EMAIL, StandardClaimNames.EMAIL_VERIFIED);
      case OidcScopes.ADDRESS:
        return Sets.newHashSet(StandardClaimNames.ADDRESS);
      case OidcScopes.PHONE:
        return Sets.newHashSet(StandardClaimNames.PHONE_NUMBER,
            StandardClaimNames.PHONE_NUMBER_VERIFIED);
      default:
        return Sets.newHashSet();
    }
  }

  @Override
  public Set<String> getClaimsForScopeSet(Set<String> scopes) {

    return scopes.stream()
      .map(this::getClaimsForScope)
      .flatMap(Set::stream)
      .collect(Collectors.toSet());
  }

}
