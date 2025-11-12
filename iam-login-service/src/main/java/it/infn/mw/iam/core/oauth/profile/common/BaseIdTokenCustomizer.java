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

import static com.nimbusds.jwt.JWTClaimNames.NOT_BEFORE;
import static it.infn.mw.iam.core.oauth.profile.common.BaseExtraClaimNames.ACR;
import static it.infn.mw.iam.core.oauth.profile.iam.IamExtraClaimNames.AMR;

import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.openid.connect.service.ScopeClaimTranslationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet.Builder;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.profile.ClaimValueHelper;
import it.infn.mw.iam.core.oauth.profile.IDTokenCustomizer;
import it.infn.mw.iam.persistence.model.IamAccount;

@SuppressWarnings("deprecation")
public abstract class BaseIdTokenCustomizer implements IDTokenCustomizer {

  public static final Logger LOG = LoggerFactory.getLogger(BaseIdTokenCustomizer.class);

  private final IamProperties properties;
  private final ClaimValueHelper claimValueHelper;
  private final ScopeClaimTranslationService scopeClaimTranslationService;

  protected BaseIdTokenCustomizer(IamProperties properties, ClaimValueHelper claimValueHelper,
      ScopeClaimTranslationService scopeClaimTranslationService) {
    this.properties = properties;
    this.claimValueHelper = claimValueHelper;
    this.scopeClaimTranslationService = scopeClaimTranslationService;
  }

  public IamProperties getIamProperties() {
    return properties;
  }

  public ClaimValueHelper getClaimValueHelper() {
    return claimValueHelper;
  }

  public ScopeClaimTranslationService getScopeClaimTranslationService() {
    return scopeClaimTranslationService;
  }

  protected final void includeAmrAndAcrClaimsIfNeeded(OAuth2Request request, Builder builder,
      OAuth2AccessTokenEntity accessToken) {

    Object amrClaim = request.getExtensions().get("amr");

    if (amrClaim instanceof String amrString) {
      try {
        ObjectMapper objectMapper = new ObjectMapper();
        String[] amrArray = objectMapper.readValue(amrString, String[].class);

        builder.claim(AMR, List.of(amrArray));

      } catch (Exception e) {
        LOG.error("Failed to deserialize amr claim", e);
      }
    }

    try {
      Object acrClaim = accessToken.getJwt().getJWTClaimsSet().getClaim(ACR);
      if (acrClaim != null) {
        builder.claim(ACR, acrClaim);
      }
    } catch (ParseException e) {
      LOG.error("Error parsing JWT claims: {}", e.getMessage());
    }
  }

  @Override
  public void customizeIdTokenClaims(Builder idClaims, ClientDetailsEntity client,
      OAuth2Request request, String sub, OAuth2AccessTokenEntity accessToken, IamAccount account) {

    Objects.requireNonNull(account, "Account must not be null");

    Set<String> requestedClaims =
        getScopeClaimTranslationService().getClaimsForScopeSet(request.getScope());

    Optional<IamAccount> optAccount = Optional.of(account);
    OAuth2Authentication oauth2auth = accessToken.getAuthenticationHolder().getAuthentication();
    for (String claim : requestedClaims) {
      Object claimValue = getClaimValueHelper().resolveClaim(claim, oauth2auth, optAccount);
      if (isValidClaimValue(claimValue)) {
        idClaims.claim(claim, claimValue);
      }
    }

    includeAmrAndAcrClaimsIfNeeded(request, idClaims, accessToken);

    idClaims.claim(NOT_BEFORE, Date.from(Instant.now()
      .minus(Duration.ofSeconds(properties.getAccessToken().getNbfOffsetSeconds()))));
  }

  protected boolean isValidClaimValue(Object value) {

    if (value instanceof Collection<?> coll) {
      return !coll.isEmpty();
    }
    return value != null;
  }
}
