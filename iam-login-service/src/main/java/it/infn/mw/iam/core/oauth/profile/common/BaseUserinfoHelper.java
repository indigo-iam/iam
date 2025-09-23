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

import java.util.Map;
import java.util.Set;

import org.springframework.security.oauth2.provider.OAuth2Authentication;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.profile.ClaimValueHelper;
import it.infn.mw.iam.core.oauth.profile.UserInfoHelper;
import it.infn.mw.iam.persistence.model.IamAccount;

@SuppressWarnings("deprecation")
public abstract class BaseUserinfoHelper implements UserInfoHelper {

  private final IamProperties properties;
  private final ClaimValueHelper claimValueHelper;

  protected BaseUserinfoHelper(IamProperties props, ClaimValueHelper claimValueHelper) {
    this.properties = props;
    this.claimValueHelper = claimValueHelper;
  }

  public IamProperties getProperties() {
    return properties;
  }

  public ClaimValueHelper getClaimValueHelper() {
    return claimValueHelper;
  }

  @Override
  public Map<String, Object> resolveScopeClaims(Set<String> scopes, IamAccount account,
      OAuth2Authentication auth) {

    return claimValueHelper.resolveClaims(claimValueHelper.resolveScopes(scopes), account, auth);
  }
}
