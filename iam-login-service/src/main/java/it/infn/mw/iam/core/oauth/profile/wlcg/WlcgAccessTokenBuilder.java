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
import static com.nimbusds.jwt.JWTClaimNames.NOT_BEFORE;
import static it.infn.mw.iam.core.oauth.profile.iam.IamExtraClaimNames.SCOPE;
import static java.util.stream.Collectors.joining;

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.Date;
import java.util.Objects;

import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.openid.connect.model.UserInfo;
import org.mitre.openid.connect.service.ScopeClaimTranslationService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTClaimsSet.Builder;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.profile.ClaimValueHelper;
import it.infn.mw.iam.core.oauth.profile.common.BaseAccessTokenBuilder;
import it.infn.mw.iam.core.oauth.profile.iam.IamExtraClaimNames;
import it.infn.mw.iam.core.oauth.scope.pdp.ScopeFilter;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;
import it.infn.mw.iam.persistence.repository.UserInfoAdapter;

@SuppressWarnings("deprecation")
public class WlcgAccessTokenBuilder extends BaseAccessTokenBuilder {

  public static final String PROFILE_VERSION = "1.0";
  public static final String ALL_AUDIENCES_VALUE = "https://wlcg.cern.ch/jwt/v1/any";

  public WlcgAccessTokenBuilder(IamProperties properties, IamAccountRepository accountRepository,
      IamTotpMfaRepository totpMfaRepository, AccountUtils accountUtils, ScopeFilter scopeFilter,
      ClaimValueHelper claimValueHelper,
      ScopeClaimTranslationService scopeClaimTranslationService) {
    super(properties, accountRepository, totpMfaRepository, accountUtils, scopeFilter,
        claimValueHelper, scopeClaimTranslationService);
  }

  @Override
  public JWTClaimsSet buildAccessToken(OAuth2AccessTokenEntity token,
      OAuth2Authentication authentication, UserInfo userInfo, Instant issueTime) {

    JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder(super.buildAccessToken(token, authentication, userInfo, issueTime));

    addWlcgVerClaim(builder);
    addWlcgGroupsClaim(builder, authentication, userInfo);
    addScopeClaimIfNotPresent(builder, token);
    addNotBeforeClaimIfNotPresent(builder, issueTime);
    addAudienceClaimIfNotPresent(builder);
    addAuthTimeClaim(builder, userInfo);

    return builder.build();
  }

  private void addAuthTimeClaim(Builder builder, UserInfo userInfo) {

    if (!Objects.isNull(userInfo)) {
      IamAccount account = ((UserInfoAdapter) userInfo).getUserinfo().getIamAccount();
      builder.claim(WlcgExtraClaimNames.AUTH_TIME,
          this.getClaimValueHelper().resolveClaim(WlcgExtraClaimNames.AUTH_TIME, account, null));
    }
  }

  private void addScopeClaimIfNotPresent(Builder builder, OAuth2AccessTokenEntity token) {
    if (!builder.getClaims().containsKey(SCOPE) && !token.getScope().isEmpty()) {
      builder.claim(SCOPE, token.getScope().stream().collect(joining(SPACE)));
    }
  }

  private void addWlcgVerClaim(Builder builder) {
    builder.claim(WlcgExtraClaimNames.WLCG_VER, WlcgJWTProfile.PROFILE_VERSION);
  }

  private void addNotBeforeClaimIfNotPresent(Builder builder, Instant issueTime) {
    if (!builder.getClaims().containsKey(NOT_BEFORE)) {
      builder.notBeforeTime(Date.from(issueTime
        .minus(Duration.ofSeconds(getProperties().getAccessToken().getNbfOffsetSeconds()))));
    }
  }

  private void addWlcgGroupsClaim(Builder builder, OAuth2Authentication authentication,
      UserInfo userInfo) {

    builder.claim(IamExtraClaimNames.GROUPS, null);
    if (!Objects.isNull(userInfo)) {
      IamAccount account = ((UserInfoAdapter) userInfo).getUserinfo().getIamAccount();
      Object value = getClaimValueHelper().resolveClaim(WlcgExtraClaimNames.WLCG_GROUPS, account,
          authentication);
      if (value instanceof Collection<?> valueColl && !valueColl.isEmpty()) {
        builder.claim(WlcgExtraClaimNames.WLCG_GROUPS, valueColl);
      }
    }
  }

  private void addAudienceClaimIfNotPresent(Builder builder) {
    if (!builder.getClaims().containsKey(AUDIENCE)) {
      builder.audience(ALL_AUDIENCES_VALUE);
    }
  }

}
