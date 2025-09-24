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

import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.ADDRESS;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.BIRTHDATE;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.EMAIL;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.EMAIL_VERIFIED;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.FAMILY_NAME;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.GENDER;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.GIVEN_NAME;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.LOCALE;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.MIDDLE_NAME;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.NAME;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.NICKNAME;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.PHONE_NUMBER;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.PHONE_NUMBER_VERIFIED;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.PICTURE;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.PREFERRED_USERNAME;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.PROFILE;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.SUB;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.UPDATED_AT;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.WEBSITE;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.ZONEINFO;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

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
  public Map<String, Object> resolveClaims(Set<String> claimNames, IamAccount account,
      OAuth2Authentication auth) {

    Map<String, Object> claims = new HashMap<>();
    for (String claim : claimNames) {
      Object value = resolveClaim(claim, account, auth);
      if (value instanceof Collection<?> valueAsCollection) {
        includeIfNotEmpty(claims, claim, valueAsCollection);
      } else {
        includeIfNotNull(claims, claim, value);
      }
    }
    return claims;
  }

  @Override
  public Object resolveClaim(String claimName, IamAccount account, OAuth2Authentication auth) {

    if (Objects.isNull(claimName) || Objects.isNull(account)) {
      return null;
    }
    switch (claimName) {
      case SUB:
        return account.getUuid();
      case NAME:
        return account.getUserInfo().getName();
      case EMAIL:
        return account.getUserInfo().getEmail();
      case EMAIL_VERIFIED:
        return account.getUserInfo().getEmailVerified();
      case PREFERRED_USERNAME:
        return account.getUsername();
      case GIVEN_NAME:
        return account.getUserInfo().getGivenName();
      case MIDDLE_NAME:
        return account.getUserInfo().getMiddleName();
      case FAMILY_NAME:
        return account.getUserInfo().getFamilyName();
      case NICKNAME:
        return account.getUserInfo().getNickname();
      case PROFILE:
        return account.getUserInfo().getProfile();
      case PICTURE:
        return account.getUserInfo().getPicture();
      case WEBSITE:
        return account.getUserInfo().getWebsite();
      case GENDER:
        return account.getUserInfo().getGender();
      case BIRTHDATE:
        return account.getUserInfo().getBirthdate();
      case ZONEINFO:
        return account.getUserInfo().getZoneinfo();
      case LOCALE:
        return account.getUserInfo().getLocale();
      case UPDATED_AT:
        return account.getLastUpdateTime().getTime();
      case ADDRESS:
        return account.getUserInfo().getAddress();
      case PHONE_NUMBER:
        return account.getUserInfo().getPhoneNumber();
      case PHONE_NUMBER_VERIFIED:
        return account.getUserInfo().getPhoneNumberVerified();
      default:
        return null;
    }
  }

  protected void includeIfNotNull(Map<String, Object> claims, String key, Object value) {

    if (value != null) {
      claims.putIfAbsent(key, value);
    }
  }

  protected void includeIfNotEmpty(Map<String, Object> claims, String key, Collection<?> value) {

    if (!value.isEmpty()) {
      claims.put(key, value);
    }
  }
}
