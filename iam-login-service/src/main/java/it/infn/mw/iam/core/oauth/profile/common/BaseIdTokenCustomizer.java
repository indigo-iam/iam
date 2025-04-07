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

import static it.infn.mw.iam.config.IamTokenEnhancerProperties.TokenContext.ID_TOKEN;
import static java.util.Objects.isNull;

import java.text.ParseException;
import java.util.List;
import java.util.Optional;

import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.provider.OAuth2Request;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet.Builder;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamTokenEnhancerProperties.IncludeLabelProperties;
import it.infn.mw.iam.core.oauth.profile.IDTokenCustomizer;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamLabel;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@SuppressWarnings("deprecation")
public abstract class BaseIdTokenCustomizer implements IDTokenCustomizer {

  public static final Logger LOG = LoggerFactory.getLogger(BaseIdTokenCustomizer.class);

  private final IamAccountRepository accountRepo;
  private final IamProperties properties;

  protected BaseIdTokenCustomizer(IamAccountRepository accountRepo, IamProperties properties) {
    this.accountRepo = accountRepo;
    this.properties = properties;
  }

  public IamAccountRepository getAccountRepo() {
    return accountRepo;
  }

  protected final void includeLabelsInIdToken(Builder idClaims, IamAccount account) {

    if (isNull(account)) {
      return;
    }

    if (isNull(properties.getTokenEnhancer())
        || isNull(properties.getTokenEnhancer().getIncludeLabels())) {
      return;
    }

    for (IncludeLabelProperties includeLabel : properties.getTokenEnhancer().getIncludeLabels()) {
      if (includeLabel.getContext().contains(ID_TOKEN)) {
        Optional<IamLabel> label = account.getLabelByPrefixAndName(
            includeLabel.getLabel().getPrefix(), includeLabel.getLabel().getName());

        if (label.isPresent()) {
          idClaims.claim(includeLabel.getClaimName(), label.get().getValue());
        }
      }
    }
  }

  protected final void includeAmrAndAcrClaimsIfNeeded(OAuth2Request request, Builder builder,
      OAuth2AccessTokenEntity accessToken) {
    Object amrClaim = request.getExtensions().get("amr");

    if (amrClaim instanceof String amrString) {
      try {
        ObjectMapper objectMapper = new ObjectMapper();
        List<String> amrList =
            objectMapper.readValue(amrString, new TypeReference<List<String>>() {});

        builder.claim("amr", amrList);

      } catch (Exception e) {
        LOG.error("Failed to deserialize amr claim", e);
      }
    }

    try {
      Object acrClaim = accessToken.getJwt().getJWTClaimsSet().getClaim("acr");
      if (acrClaim != null) {
        builder.claim("acr", acrClaim);
      }
    } catch (ParseException e) {
      LOG.error("Error parsing JWT claims: {}", e.getMessage());
    }
  }
}
