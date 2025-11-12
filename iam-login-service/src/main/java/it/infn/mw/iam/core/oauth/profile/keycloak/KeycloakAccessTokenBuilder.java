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
package it.infn.mw.iam.core.oauth.profile.keycloak;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;

import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.openid.connect.service.ScopeClaimTranslationService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import com.nimbusds.jwt.JWTClaimsSet;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.profile.ClaimValueHelper;
import it.infn.mw.iam.core.oauth.profile.common.BaseAccessTokenBuilder;
import it.infn.mw.iam.core.oauth.scope.pdp.ScopeFilter;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;

@SuppressWarnings("deprecation")
public class KeycloakAccessTokenBuilder extends BaseAccessTokenBuilder {

  public KeycloakAccessTokenBuilder(IamProperties properties,
      IamTotpMfaRepository totpMfaRepository, AccountUtils accountUtils, ScopeFilter scopeFilter,
      ClaimValueHelper claimValueHelper,
      ScopeClaimTranslationService scopeClaimTranslationService) {
    super(properties, totpMfaRepository, accountUtils, scopeFilter, claimValueHelper,
        scopeClaimTranslationService);
  }

  @Override
  public JWTClaimsSet buildAccessToken(OAuth2AccessTokenEntity token,
      OAuth2Authentication authentication, Optional<IamAccount> account, Instant issueTime) {

    JWTClaimsSet.Builder builder =
        new JWTClaimsSet.Builder(super.buildAccessToken(token, authentication, account, issueTime));

    if (account.isPresent()) {
      Set<String> groupNames =
          KeycloakGroupHelper.resolveGroupNames(account.get().getUserInfo().getGroups());
      if (!groupNames.isEmpty()) {
        builder.claim(KeycloakExtraClaimNames.ROLES, groupNames);
      }
    }

    return builder.build();
  }

  @Override
  protected boolean isIncludeNbf() {

    return true;
  }

  @Override
  protected boolean isIncludeScope() {

    return true;
  }
}
