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
package it.infn.mw.iam.core.oauth.profile.wlcg;

import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import it.infn.mw.iam.authn.ExternalAuthenticationInfoProcessor;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.profile.iam.IamJWTProfileUserinfoHelper;
import it.infn.mw.iam.persistence.model.IamAccount;

@SuppressWarnings("deprecation")
public class WLCGJWTUserinfoHelper extends IamJWTProfileUserinfoHelper {

  public static final Logger LOG = LoggerFactory.getLogger(WLCGJWTUserinfoHelper.class);

  private final WLCGGroupHelper groupHelper;

  public WLCGJWTUserinfoHelper(IamProperties props, ExternalAuthenticationInfoProcessor proc,
      WLCGGroupHelper groupHelper) {
    super(props, proc);
    this.groupHelper = groupHelper;
  }

  @Override
  public Map<String, Object> resolveScopeClaims(OAuth2Authentication auth, Set<String> scopes,
      IamAccount account) {

    Map<String, Object> claims = super.resolveScopeClaims(auth, scopes, account);
    claims.remove("groups");
    claims.remove("organisation_name");
    Set<String> resolvedGroups = groupHelper.resolveGroupNames(scopes, account.getUserInfo());
    if (!resolvedGroups.isEmpty()) {
      claims.put(WlcgExtraClaimNames.WLCG_GROUPS, resolvedGroups);
    }
    return claims;
  }
}
