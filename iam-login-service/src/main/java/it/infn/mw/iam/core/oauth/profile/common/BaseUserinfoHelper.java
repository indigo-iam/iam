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
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.profile.UserInfoHelper;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.model.IamUserInfo;

@SuppressWarnings("deprecation")
public abstract class BaseUserinfoHelper implements UserInfoHelper {

  private final IamProperties properties;

  public BaseUserinfoHelper(IamProperties props) {
    this.properties = props;
  }

  public IamProperties getProperties() {
    return properties;
  }

  protected void includeIfNotNull(Map<String, Object> claims, String key, Object value) {

    if (value != null) {
      claims.putIfAbsent(key, value);
    }
  }

  protected void includeIfNotEmpty(Map<String, Object> claims, String key,
      Collection<String> value) {

    if (!value.isEmpty()) {
      claims.putIfAbsent(key, value);
    }
  }

  protected Collection<String> getGroupsAsStringSet(Set<IamGroup> groups) {
    return groups.stream().map(IamGroup::getName).collect(Collectors.toSet());
  }

  @Override
  public Map<String, Object> resolveScopeClaims(OAuth2Authentication auth, Set<String> scopes,
      IamAccount account) {

    Map<String, Object> claims = new HashMap<>();
    IamUserInfo ui = account.getUserInfo();

    for (String scope : scopes) {
      switch (scope) {
        case OidcScopes.OPENID:
          claims.put(SUB, account.getUuid());
          break;
        case OidcScopes.PROFILE:
          includeIfNotNull(claims, NAME, ui.getName());
          includeIfNotNull(claims, GIVEN_NAME, ui.getGivenName());
          includeIfNotNull(claims, MIDDLE_NAME, ui.getMiddleName());
          includeIfNotNull(claims, FAMILY_NAME, ui.getFamilyName());
          includeIfNotNull(claims, NICKNAME, ui.getNickname());
          includeIfNotNull(claims, PREFERRED_USERNAME, account.getUsername());
          includeIfNotNull(claims, PROFILE, ui.getProfile());
          includeIfNotNull(claims, PICTURE, ui.getPicture());
          includeIfNotNull(claims, WEBSITE, ui.getWebsite());
          includeIfNotNull(claims, GENDER, ui.getGender());
          includeIfNotNull(claims, BIRTHDATE, ui.getBirthdate());
          includeIfNotNull(claims, ZONEINFO, ui.getZoneinfo());
          includeIfNotNull(claims, LOCALE, ui.getLocale());
          includeIfNotNull(claims, UPDATED_AT, account.getLastUpdateTime().getTime());
          break;
        case OidcScopes.EMAIL:
          claims.put(EMAIL, ui.getEmail());
          claims.put(EMAIL_VERIFIED, ui.getEmailVerified());
          break;
        case OidcScopes.ADDRESS:
          includeIfNotNull(claims, ADDRESS, ui.getAddress());
          break;
        case OidcScopes.PHONE:
          includeIfNotNull(claims, PHONE_NUMBER, ui.getPhoneNumber());
          includeIfNotNull(claims, PHONE_NUMBER_VERIFIED, ui.getPhoneNumberVerified());
        default:
          break;
      }
    }
    return claims;
  }

}
