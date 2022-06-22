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

import static it.infn.mw.iam.core.oauth.profile.aarc.AarcClaimValueHelper.ADDITIONAL_CLAIMS;
import static java.util.Objects.isNull;

import java.time.Instant;
import java.util.Set;

import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.openid.connect.model.UserInfo;
import org.mitre.openid.connect.service.ScopeClaimTranslationService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTClaimsSet.Builder;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.profile.common.BaseAccessTokenBuilder;
import it.infn.mw.iam.persistence.repository.UserInfoAdapter;

@SuppressWarnings("deprecation")
public class AarcJWTProfileAccessTokenBuilder extends BaseAccessTokenBuilder {

  protected final ScopeClaimTranslationService scopeClaimConverter;
  protected final AarcClaimValueHelper claimValueHelper;

  public AarcJWTProfileAccessTokenBuilder(IamProperties properties,
      ScopeClaimTranslationService scopeClaimConverter, AarcClaimValueHelper claimValueHelper) {
    super(properties);
    this.scopeClaimConverter = scopeClaimConverter;
    this.claimValueHelper = claimValueHelper;
  }

  @Override
  public JWTClaimsSet buildAccessToken(OAuth2AccessTokenEntity token,
      OAuth2Authentication authentication, UserInfo userInfo, Instant issueTime) {

    Builder builder = baseJWTSetup(token, authentication, userInfo, issueTime);

    if (!isNull(userInfo)) {
      Set<String> requiredClaims = scopeClaimConverter.getClaimsForScopeSet(token.getScope());

      requiredClaims.stream()
        .filter(ADDITIONAL_CLAIMS::contains)
        .forEach(c -> builder.claim(c, claimValueHelper.getClaimValueFromUserInfo(c,
            ((UserInfoAdapter) userInfo).getUserinfo())));
    }

    return builder.build();
  }

}
