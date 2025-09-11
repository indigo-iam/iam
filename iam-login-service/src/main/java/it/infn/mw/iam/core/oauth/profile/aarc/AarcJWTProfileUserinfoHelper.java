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
package it.infn.mw.iam.core.oauth.profile.aarc;

import java.util.Map;
import java.util.Set;

import org.springframework.security.oauth2.provider.OAuth2Authentication;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.profile.common.BaseUserinfoHelper;
import it.infn.mw.iam.persistence.model.IamAccount;

@SuppressWarnings("deprecation")
public class AarcJWTProfileUserinfoHelper extends BaseUserinfoHelper {

  protected final AarcClaimValueHelper claimValueHelper;

  public AarcJWTProfileUserinfoHelper(IamProperties props,
      AarcClaimValueHelper claimValueHelper) {
    super(props);
    this.claimValueHelper = claimValueHelper;
  }

  @Override
  public Map<String, Object> resolveScopeClaims(OAuth2Authentication auth, Set<String> scopes, IamAccount account) {

    Map<String, Object> claims = super.resolveScopeClaims(auth, scopes, account);
    claims.remove("groups");
    scopes.forEach(scope -> includeIfNotNull(claims, scope,
        claimValueHelper.getClaimValueFromUserInfo(scope, account.getUserInfo())));
    return claims;
  }

}
