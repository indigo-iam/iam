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

import static com.nimbusds.jwt.JWTClaimNames.AUDIENCE;
import static it.infn.mw.iam.core.oauth.attributes.AttributeMapHelper.ATTR_SCOPE;
import static java.util.Objects.isNull;
import static java.util.stream.Collectors.joining;

import java.time.Instant;
import java.util.Date;
import java.util.Set;

import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.openid.connect.model.UserInfo;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTClaimsSet.Builder;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.attributes.AttributeMapHelper;
import it.infn.mw.iam.core.oauth.profile.common.BaseAccessTokenBuilder;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;
import it.infn.mw.iam.core.oauth.scope.pdp.ScopeFilter;
import it.infn.mw.iam.persistence.repository.UserInfoAdapter;

@SuppressWarnings("deprecation")
public class WLCGProfileAccessTokenBuilder extends BaseAccessTokenBuilder {

  public static final String WLCG_VER_CLAIM = "wlcg.ver";
  public static final String PROFILE_VERSION = "1.0";
  public static final String ALL_AUDIENCES_VALUE = "https://wlcg.cern.ch/jwt/v1/any";

  final WLCGGroupHelper groupHelper;
  final AttributeMapHelper attributeHelper;

  public WLCGProfileAccessTokenBuilder(IamProperties properties,
      AttributeMapHelper attributeHelper, IamTotpMfaRepository totpMfaRepository,
      AccountUtils accountUtils, WLCGGroupHelper groupHelper, ScopeFilter scopeFilter) {
    super(properties, totpMfaRepository, accountUtils, scopeFilter);
    this.groupHelper = groupHelper;
    this.attributeHelper = attributeHelper;
  }


  @Override
  public JWTClaimsSet buildAccessToken(OAuth2AccessTokenEntity token,
      OAuth2Authentication authentication, UserInfo userInfo, Instant issueTime) {

    Builder builder = baseJWTSetup(token, authentication, userInfo, issueTime);

    builder.notBeforeTime(Date.from(issueTime));

    addScopeClaim(builder, token);
    addWlcgVerClaim(builder);

    if (!isNull(userInfo)) {
      Set<String> groupNames =
          groupHelper.resolveGroupNames(token, ((UserInfoAdapter) userInfo).getUserinfo());
      addWlcgGroupsScopeClaim(builder, groupNames);

      if (token.getScope().contains(ATTR_SCOPE)) {
        addAttributeScopeClaim(builder, userInfo);
      }
      if (properties.getAccessToken().isIncludeAuthnInfo()) {
        addAuthnInfoClaims(builder, token.getScope(), userInfo);
      }

      if (token.getScope().contains(ATTR_SCOPE)) {
        builder.claim(ATTR_SCOPE, attributeHelper
          .getAttributeMapFromUserInfo(((UserInfoAdapter) userInfo).getUserinfo()));
      }
    }

    addAudience(builder);

    return builder.build();
  }

  private void addScopeClaim(Builder builder, OAuth2AccessTokenEntity token) {
    if (!token.getScope().isEmpty()) {
      builder.claim(SCOPE_CLAIM_NAME, token.getScope().stream().collect(joining(SPACE)));
    }
  }

  private void addWlcgVerClaim(Builder builder) {
    builder.claim(WLCG_VER_CLAIM, PROFILE_VERSION);
  }

  private void addWlcgGroupsScopeClaim(Builder builder, Set<String> groupNames) {
    if (!groupNames.isEmpty()) {
      builder.claim(WLCGGroupHelper.WLCG_GROUPS_SCOPE, groupNames);
    }
  }

  private void addAttributeScopeClaim(Builder builder, UserInfo userInfo) {
    builder.claim(ATTR_SCOPE,
        attributeHelper.getAttributeMapFromUserInfo(((UserInfoAdapter) userInfo).getUserinfo()));
  }

  private void addAuthnInfoClaims(Builder builder, Set<String> scopes, UserInfo userInfo) {
    if (scopes.contains("email")) {
      builder.claim("email", userInfo.getEmail());
    }
    if (scopes.contains("profile")) {
      builder.claim("preferred_username", userInfo.getPreferredUsername());
      builder.claim("name", userInfo.getName());
    }
  }

  private void addAudience(Builder builder) {
    if (!builder.getClaims().containsKey(AUDIENCE)) {
      builder.audience(ALL_AUDIENCES_VALUE);
    }
  }

}
