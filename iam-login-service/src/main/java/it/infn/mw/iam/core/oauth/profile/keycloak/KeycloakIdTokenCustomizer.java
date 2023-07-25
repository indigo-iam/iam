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

import java.util.Set;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.openid.connect.service.ScopeClaimTranslationService;
import org.springframework.security.oauth2.provider.OAuth2Request;

import com.nimbusds.jwt.JWTClaimsSet.Builder;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.profile.iam.ClaimValueHelper;
import it.infn.mw.iam.core.oauth.profile.iam.IamJWTProfileIdTokenCustomizer;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamUserInfo;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@SuppressWarnings("deprecation")
public class KeycloakIdTokenCustomizer extends IamJWTProfileIdTokenCustomizer {

  private final KeycloakGroupHelper groupHelper;

  public KeycloakIdTokenCustomizer(IamAccountRepository accountRepo,
      ScopeClaimTranslationService scopeClaimConverter, ClaimValueHelper claimValueHelper,
      KeycloakGroupHelper groupHelper, IamProperties properties) {
    super(accountRepo, scopeClaimConverter, claimValueHelper, properties);
    this.groupHelper = groupHelper;
  }

  @Override
  public void customizeIdTokenClaims(Builder idClaims, ClientDetailsEntity client,
      OAuth2Request request, String sub, OAuth2AccessTokenEntity accessToken, IamAccount account) {

    super.customizeIdTokenClaims(idClaims, client, request, sub, accessToken, account);

    IamUserInfo info = account.getUserInfo();
    Set<String> groupNames = groupHelper.resolveGroupNames(info);

    if (!groupNames.isEmpty()) {
      idClaims.claim(KeycloakGroupHelper.KEYCLOAK_ROLES_CLAIM, groupNames);
    }

    // Drop group claims as set by IAM JWT profile
    idClaims.claim("groups", null);

    includeLabelsInIdToken(idClaims, account);

  }

}
