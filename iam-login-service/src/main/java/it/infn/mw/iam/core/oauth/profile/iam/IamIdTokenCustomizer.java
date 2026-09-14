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

import static it.infn.mw.iam.config.IamTokenEnhancerProperties.TokenContext.ID_TOKEN;

import java.util.Optional;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

import com.nimbusds.jwt.JWTClaimsSet.Builder;

import it.infn.mw.iam.authn.oidc.OidcExternalAuthenticationToken;
import it.infn.mw.iam.authn.saml.SamlExternalAuthenticationToken;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamTokenEnhancerProperties.IncludeLabelProperties;
import it.infn.mw.iam.core.oauth.profile.ClaimValueHelper;
import it.infn.mw.iam.core.oauth.profile.ScopeClaimTranslationService;
import it.infn.mw.iam.core.oauth.profile.common.BaseIdTokenCustomizer;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamLabel;
import it.infn.mw.iam.persistence.model.OAuth2AccessTokenEntity;
import it.infn.mw.iam.persistence.model.SavedUserAuthentication;

@SuppressWarnings("deprecation")
public class IamIdTokenCustomizer extends BaseIdTokenCustomizer {

  public IamIdTokenCustomizer(IamProperties properties, ClaimValueHelper claimValueHelper,
      ScopeClaimTranslationService scopeClaimTranslationService) {
    super(properties, claimValueHelper, scopeClaimTranslationService);
  }

  protected final void includeLabelsInIdToken(Builder idClaims, IamAccount account) {

    for (IncludeLabelProperties includeLabel : getProperties().getTokenEnhancer()
      .getIncludeLabels()) {
      if (includeLabel.getContext().contains(ID_TOKEN)) {
        Optional<IamLabel> label = account.getLabelByPrefixAndName(
            includeLabel.getLabel().getPrefix(), includeLabel.getLabel().getName());

        if (label.isPresent()) {
          idClaims.claim(includeLabel.getClaimName(), label.get().getValue());
        }
      }
    }
  }

  @Override
  public void customizeIdTokenClaims(Builder idClaims, ClientDetailsEntity client,
      OAuth2Request request, String sub, OAuth2AccessTokenEntity accessToken, IamAccount account) {

    super.customizeIdTokenClaims(idClaims, client, request, sub, accessToken, account);

    includeLabelsInIdToken(idClaims, account);
    includeExternalAuthnInIdToken(idClaims, accessToken, account);
  }

  protected void includeExternalAuthnInIdToken(Builder idClaims,
      OAuth2AccessTokenEntity accessToken, IamAccount account) {

    Authentication oauth2auth =
        accessToken.getAuthenticationHolder().getAuthentication().getUserAuthentication();

    if (isExternalAuthn(oauth2auth)) {
      idClaims.claim(IamExtraClaimNames.EXTERNAL_AUTHN,
          getClaimValueHelper().resolveClaim(IamExtraClaimNames.EXTERNAL_AUTHN,
              accessToken.getAuthenticationHolder().getAuthentication(), Optional.of(account)));
    }
  }

  protected boolean isExternalAuthn(Authentication auth) {
    if (auth instanceof SavedUserAuthentication savedAuth) {

      String sourceClass = savedAuth.getSourceClass();
      return sourceClass != null
          && (sourceClass.equals(SamlExternalAuthenticationToken.class.getName())
              || sourceClass.equals(OidcExternalAuthenticationToken.class.getName()));
    }
    return false;
  }
}
