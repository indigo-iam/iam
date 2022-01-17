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
package it.infn.mw.iam.core.oauth.profile.iam;

import static it.infn.mw.iam.core.oauth.profile.iam.ClaimValueHelper.ADDITIONAL_CLAIMS;

import java.util.Set;

import com.nimbusds.jwt.JWTClaimsSet.Builder;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.openid.connect.service.ScopeClaimTranslationService;
import org.springframework.security.oauth2.provider.OAuth2Request;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.profile.common.BaseIdTokenCustomizer;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAuthenticationMethodReference;
import it.infn.mw.iam.persistence.model.IamUserInfo;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@SuppressWarnings("deprecation")
public class IamJWTProfileIdTokenCustomizer extends BaseIdTokenCustomizer {

  protected final ScopeClaimTranslationService scopeClaimConverter;
  protected final ClaimValueHelper claimValueHelper;

  public IamJWTProfileIdTokenCustomizer(IamAccountRepository accountRepo,
      ScopeClaimTranslationService scopeClaimConverter, ClaimValueHelper claimValueHelper,
      IamProperties properties) {
    super(accountRepo, properties);
    this.scopeClaimConverter = scopeClaimConverter;
    this.claimValueHelper = claimValueHelper;
  }


  @Override
  public void customizeIdTokenClaims(Builder idClaims, ClientDetailsEntity client,
      OAuth2Request request, String sub, OAuth2AccessTokenEntity accessToken, IamAccount account) {

    IamUserInfo info = account.getUserInfo();

    Set<String> requiredClaims = scopeClaimConverter.getClaimsForScopeSet(request.getScope());

    // Add the methods of authentication to the id_token
    Set<IamAuthenticationMethodReference> refs = account.getAuthenticationMethodReferences();
    String[] amr =
        refs.stream().map(IamAuthenticationMethodReference::getName).toArray(String[]::new);
    idClaims.claim("amr", amr);

    requiredClaims.stream()
      .filter(ADDITIONAL_CLAIMS::contains)
      .forEach(c -> idClaims.claim(c, claimValueHelper.getClaimValueFromUserInfo(c, info)));

    includeLabelsInIdToken(idClaims, account);
  }

}
