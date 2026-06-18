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

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import com.nimbusds.jwt.JWTClaimNames;

import it.infn.mw.iam.core.oauth.profile.ClaimValueHelper;
import it.infn.mw.iam.persistence.model.IamAccount;

@SuppressWarnings("deprecation")
public abstract class BaseClaimValueHelper implements ClaimValueHelper {

  protected static final Set<String> OPENID_CLAIMS = Set.of(StandardClaimNames.SUB);

  protected static final Set<String> PROFILE_CLAIMS = Set.of(StandardClaimNames.NAME,
      StandardClaimNames.GIVEN_NAME, StandardClaimNames.MIDDLE_NAME, StandardClaimNames.FAMILY_NAME,
      StandardClaimNames.NICKNAME, StandardClaimNames.PREFERRED_USERNAME,
      StandardClaimNames.PROFILE, StandardClaimNames.PICTURE, StandardClaimNames.WEBSITE,
      StandardClaimNames.GENDER, StandardClaimNames.BIRTHDATE, StandardClaimNames.ZONEINFO,
      StandardClaimNames.LOCALE, StandardClaimNames.UPDATED_AT);

  protected static final Set<String> EMAIL_CLAIMS =
      Set.of(StandardClaimNames.EMAIL, StandardClaimNames.EMAIL_VERIFIED);

  protected static final Set<String> ADDRESS_CLAIMS = Set.of(StandardClaimNames.ADDRESS);

  protected static final Set<String> PHONE_CLAIMS =
      Set.of(StandardClaimNames.PHONE_NUMBER, StandardClaimNames.PHONE_NUMBER_VERIFIED);

  @Override
  public Map<String, Object> resolveClaims(Set<String> claimNames,
      OAuth2Authentication auth, Optional<IamAccount> account) {

    Map<String, Object> claims = new HashMap<>();
    claimNames.forEach(
        claimName -> includeIfValid(claims, claimName, resolveClaim(claimName, auth, account)));
    return claims;
  }

  @Override
  public Object resolveClaim(String claimName, OAuth2Authentication auth, Optional<IamAccount> account) {

    if (account.isEmpty()) {
      return null;
    }
    switch (claimName) {
      case JWTClaimNames.SUBJECT:
        return account.get().getUuid();
      case StandardClaimNames.NAME:
        return account.get().getUserInfo().getName();
      case StandardClaimNames.EMAIL:
        return account.get().getUserInfo().getEmail();
      case StandardClaimNames.EMAIL_VERIFIED:
        return account.get().getUserInfo().getEmailVerified();
      case StandardClaimNames.PREFERRED_USERNAME:
        return account.get().getUsername();
      case StandardClaimNames.GIVEN_NAME:
        return account.get().getUserInfo().getGivenName();
      case StandardClaimNames.MIDDLE_NAME:
        return account.get().getUserInfo().getMiddleName();
      case StandardClaimNames.FAMILY_NAME:
        return account.get().getUserInfo().getFamilyName();
      case StandardClaimNames.NICKNAME:
        return account.get().getUserInfo().getNickname();
      case StandardClaimNames.PROFILE:
        return account.get().getUserInfo().getProfile();
      case StandardClaimNames.PICTURE:
        return account.get().getUserInfo().getPicture();
      case StandardClaimNames.WEBSITE:
        return account.get().getUserInfo().getWebsite();
      case StandardClaimNames.GENDER:
        return account.get().getUserInfo().getGender();
      case StandardClaimNames.BIRTHDATE:
        return account.get().getUserInfo().getBirthdate();
      case StandardClaimNames.ZONEINFO:
        return account.get().getUserInfo().getZoneinfo();
      case StandardClaimNames.LOCALE:
        return account.get().getUserInfo().getLocale();
      case StandardClaimNames.UPDATED_AT:
        /* account.get().getLastUpdateTime() cannot be null */
        return account.get().getLastUpdateTime().getTime() / 1000;
      case StandardClaimNames.ADDRESS:
        return account.get().getUserInfo().getAddress();
      case StandardClaimNames.PHONE_NUMBER:
        return account.get().getUserInfo().getPhoneNumber();
      case StandardClaimNames.PHONE_NUMBER_VERIFIED:
        return account.get().getUserInfo().getPhoneNumberVerified();
      default:
        return null;
    }
  }

  public boolean isValidClaimValue(Object value) {

    if (value instanceof Collection<?> coll) {
      return !coll.isEmpty();
    }
    if (value instanceof String s) {
      return !s.trim().isEmpty();
    }
    return value != null;
  }

  protected void includeIfValid(Map<String, Object> claims, String key, Object value) {

    if (isValidClaimValue(value)) {
      claims.put(key, value);
    }
  }
}
