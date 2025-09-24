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

import static it.infn.mw.iam.config.IamTokenEnhancerProperties.TokenContext.USERINFO;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.mitre.openid.connect.service.ScopeClaimTranslationService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamTokenEnhancerProperties.IncludeLabelProperties;
import it.infn.mw.iam.core.oauth.profile.ClaimValueHelper;
import it.infn.mw.iam.core.oauth.profile.common.BaseUserinfoHelper;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamLabel;

@SuppressWarnings("deprecation")
public class IamUserinfoHelper extends BaseUserinfoHelper {

  public IamUserinfoHelper(IamProperties props, ClaimValueHelper claimValueHelper,
      ScopeClaimTranslationService scopeTranslationService) {
    super(props, claimValueHelper, scopeTranslationService);
  }

  @Override
  public Map<String, Object> resolveScopeClaims(Set<String> scopes, IamAccount account,
      OAuth2Authentication auth) {

    Map<String, Object> claims = super.resolveScopeClaims(scopes, account, auth);
    includeLabelsInUserinfo(claims, account);
    return claims;
  }

  private void includeLabelsInUserinfo(Map<String, Object> claims, IamAccount account) {

    for (IncludeLabelProperties includeLabel : getProperties().getTokenEnhancer()
      .getIncludeLabels()) {
      if (includeLabel.getContext().contains(USERINFO)) {
        Optional<IamLabel> label = account.getLabelByPrefixAndName(
            includeLabel.getLabel().getPrefix(), includeLabel.getLabel().getName());
        if (label.isPresent()) {
          claims.put(includeLabel.getClaimName(), label.get().getValue());
        }
      }
    }
  }
}
