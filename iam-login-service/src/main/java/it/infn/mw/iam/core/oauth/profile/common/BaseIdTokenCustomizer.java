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

import java.util.Optional;

import com.nimbusds.jwt.JWTClaimsSet.Builder;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamTokenEnhancerProperties.IncludeLabelProperties;
import it.infn.mw.iam.core.oauth.profile.IDTokenCustomizer;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamLabel;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

public abstract class BaseIdTokenCustomizer implements IDTokenCustomizer {

  private final IamAccountRepository accountRepo;
  private final IamProperties properties;

  public BaseIdTokenCustomizer(IamAccountRepository accountRepo, IamProperties properties) {
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

}
