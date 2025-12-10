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

import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.mitre.openid.connect.service.ScopeClaimTranslationService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import com.nimbusds.jwt.JWTClaimNames;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.profile.ClaimValueHelper;
import it.infn.mw.iam.core.oauth.profile.UserInfoHelper;
import it.infn.mw.iam.persistence.model.IamAccount;

@SuppressWarnings("deprecation")
public abstract class BaseUserinfoHelper implements UserInfoHelper {

  private final IamProperties properties;
  private final ClaimValueHelper claimValueHelper;
  private final ScopeClaimTranslationService scopeTranslationService;

  protected BaseUserinfoHelper(IamProperties props, ClaimValueHelper claimValueHelper,
      ScopeClaimTranslationService scopeTranslationService) {
    this.properties = props;
    this.claimValueHelper = claimValueHelper;
    this.scopeTranslationService = scopeTranslationService;
  }

  public IamProperties getProperties() {
    return properties;
  }

  public ClaimValueHelper getClaimValueHelper() {
    return claimValueHelper;
  }

  public ScopeClaimTranslationService getScopeTranslationService() {
    return scopeTranslationService;
  }

  @Override
  public Set<String> getRequiredClaims() {
    return Set.of(JWTClaimNames.SUBJECT);
  }

  @Override
  public Map<String, Object> resolveScopeClaims(Set<String> scopes, IamAccount account,
      OAuth2Authentication auth) {

    Set<String> claimNames = new HashSet<>();
    claimNames.addAll(getRequiredClaims());
    claimNames.addAll(scopeTranslationService.getClaimsForScopeSet(scopes));
    Map<String, Object> claims = claimValueHelper.resolveClaims(claimNames, auth, Optional.of(account));
    claims.put("scope", scopes);
    return claims;
  }
}
