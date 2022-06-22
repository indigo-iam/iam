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

import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.service.IntrospectionResultAssembler;
import org.mitre.openid.connect.model.UserInfo;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.profile.common.BaseIntrospectionHelper;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcherRegistry;
import it.infn.mw.iam.persistence.repository.UserInfoAdapter;


public class WLCGIntrospectionHelper extends BaseIntrospectionHelper {

  private final WLCGGroupHelper groupHelper;

  public WLCGIntrospectionHelper(IamProperties props, IntrospectionResultAssembler assembler,
      ScopeMatcherRegistry registry, WLCGGroupHelper helper) {
    super(props, assembler, registry);
    this.groupHelper = helper;
  }

  @Override
  public Map<String, Object> assembleIntrospectionResult(OAuth2AccessTokenEntity accessToken,
      UserInfo userInfo, Set<String> authScopes) {

    Map<String, Object> result = getAssembler().assembleFrom(accessToken, userInfo, authScopes);

    addIssuerClaim(result);
    addAudience(result, accessToken);
    addScopeClaim(result, filterScopes(accessToken, authScopes));
    
    Set<String> groups =
        groupHelper.resolveGroupNames(accessToken, ((UserInfoAdapter) userInfo).getUserinfo());

    if (!groups.isEmpty()) {
      result.put(WLCGGroupHelper.WLCG_GROUPS_SCOPE, groups);
    }

    return result;
  }

}
