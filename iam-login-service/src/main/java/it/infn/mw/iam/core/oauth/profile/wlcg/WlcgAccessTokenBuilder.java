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

import static it.infn.mw.iam.core.oauth.profile.iam.IamExtraClaimNames.ATTR;
import static it.infn.mw.iam.core.oauth.profile.iam.IamExtraClaimNames.SSH_KEYS;
import static it.infn.mw.iam.core.oauth.profile.wlcg.WlcgExtraClaimNames.AUTH_TIME;
import static it.infn.mw.iam.core.oauth.profile.wlcg.WlcgExtraClaimNames.WLCG_GROUPS;
import static it.infn.mw.iam.core.oauth.profile.wlcg.WlcgExtraClaimNames.WLCG_VER;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.EMAIL;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.NAME;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.PREFERRED_USERNAME;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;

import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.openid.connect.service.ScopeClaimTranslationService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTClaimsSet.Builder;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.profile.ClaimValueHelper;
import it.infn.mw.iam.core.oauth.profile.common.BaseAccessTokenBuilder;
import it.infn.mw.iam.core.oauth.scope.pdp.ScopeFilter;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;

@SuppressWarnings("deprecation")
public class WlcgAccessTokenBuilder extends BaseAccessTokenBuilder {

  public static final String PROFILE_VERSION = "1.0";
  public static final String ALL_AUDIENCES_VALUE = "https://wlcg.cern.ch/jwt/v1/any";

  public WlcgAccessTokenBuilder(IamProperties properties, IamTotpMfaRepository totpMfaRepository,
      AccountUtils accountUtils, ScopeFilter scopeFilter, ClaimValueHelper claimValueHelper,
      ScopeClaimTranslationService scopeClaimTranslationService) {
    super(properties, totpMfaRepository, accountUtils, scopeFilter, claimValueHelper,
        scopeClaimTranslationService);
  }

  @Override
  public Set<String> getAdditionalAuthnInfoClaims() {

    return Set.of(NAME, EMAIL, PREFERRED_USERNAME, ATTR, SSH_KEYS);
  }

  @Override
  public JWTClaimsSet buildAccessToken(OAuth2AccessTokenEntity token,
      OAuth2Authentication authentication, Optional<IamAccount> account, Instant issueTime) {

    JWTClaimsSet.Builder builder =
        new JWTClaimsSet.Builder(super.buildAccessToken(token, authentication, account, issueTime));

    /* wlcg.ver required claim */
    builder.claim(WLCG_VER, WlcgJWTProfile.PROFILE_VERSION);

    if (account.isPresent()) {

      /* add wlcg.groups */
      Set<String> groups = WlcgGroupHelper.resolveGroupNames(
          authentication.getOAuth2Request().getScope(), account.get().getUserInfo().getGroups());
      if (isValidClaimValue(groups)) {
        builder.claim(WLCG_GROUPS, groups);
      }
      /* add auth_time claim */
      Object authTime = getClaimValueHelper().resolveClaim(AUTH_TIME, authentication, account);
      if (isValidClaimValue(authTime)) {
        builder.claim(AUTH_TIME, authTime);
      }
    }

    return builder.build();
  }

  @Override
  protected boolean isIncludeScope() {

    /* scope claim is required */
    return true;
  }

  @Override
  protected boolean isIncludeNbf() {

    return true;
  }

  @Override
  protected boolean hasAudience(OAuth2Authentication authentication) {

    /* always triggers audience inclusion because it's required */
    return true;
  }

  @Override
  protected void addAudience(Builder builder, OAuth2Authentication authentication) {

    super.addAudience(builder, authentication);
    if (!builder.getClaims().containsKey(JWTClaimNames.AUDIENCE)) {
      builder.claim(JWTClaimNames.AUDIENCE, ALL_AUDIENCES_VALUE);
    }
  }

}
