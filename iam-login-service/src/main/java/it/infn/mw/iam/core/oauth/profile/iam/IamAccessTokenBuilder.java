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

import static it.infn.mw.iam.core.oauth.profile.iam.IamExtraClaimNames.ATTR;
import static it.infn.mw.iam.core.oauth.profile.iam.IamExtraClaimNames.GROUPS;
import static it.infn.mw.iam.core.oauth.profile.iam.IamExtraClaimNames.ORGANISATION_NAME;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.EMAIL;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.NAME;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.PREFERRED_USERNAME;

import java.util.Set;

import org.mitre.openid.connect.service.ScopeClaimTranslationService;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.profile.ClaimValueHelper;
import it.infn.mw.iam.core.oauth.profile.common.BaseAccessTokenBuilder;
import it.infn.mw.iam.core.oauth.scope.pdp.ScopeFilter;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;

public class IamAccessTokenBuilder extends BaseAccessTokenBuilder {

  public IamAccessTokenBuilder(IamProperties properties, IamTotpMfaRepository totpMfaRepository,
      AccountUtils accountUtils, ScopeFilter scopeFilter, ClaimValueHelper claimValueHelper,
      ScopeClaimTranslationService scopeClaimTranslationService) {
    super(properties, totpMfaRepository, accountUtils, scopeFilter, claimValueHelper,
        scopeClaimTranslationService);
  }

  @Override
  public Set<String> getAdditionalAuthnInfoClaims() {

    return Set.of(NAME, EMAIL, PREFERRED_USERNAME, ORGANISATION_NAME, GROUPS, ATTR);
  }
}
