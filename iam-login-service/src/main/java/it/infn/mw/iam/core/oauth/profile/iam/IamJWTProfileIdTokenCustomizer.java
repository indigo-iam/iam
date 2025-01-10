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

import java.util.List;
import java.util.Set;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.openid.connect.service.ScopeClaimTranslationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.provider.OAuth2Request;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet.Builder;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.IamOAuth2RequestFactory;
import it.infn.mw.iam.core.oauth.profile.common.BaseIdTokenCustomizer;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamUserInfo;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@SuppressWarnings("deprecation")
public class IamJWTProfileIdTokenCustomizer extends BaseIdTokenCustomizer {

  public static final Logger LOG = LoggerFactory.getLogger(IamOAuth2RequestFactory.class);

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

    requiredClaims.stream()
      .filter(ADDITIONAL_CLAIMS::contains)
      .forEach(c -> idClaims.claim(c, claimValueHelper.getClaimValueFromUserInfo(c, info)));

    Object amrClaim = request.getExtensions().get("amr");

    if (amrClaim instanceof String amrString) {
      try {
        ObjectMapper objectMapper = new ObjectMapper();
        List<String> amrList =
            objectMapper.readValue(amrString, new TypeReference<List<String>>() {});

        idClaims.claim("amr", amrList);
      } catch (Exception e) {
        LOG.error("Failed to deserialize amr claim", e);
      }
    }

    includeLabelsInIdToken(idClaims, account);
  }
}
