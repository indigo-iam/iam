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

import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.service.IntrospectionResultAssembler;
import org.mitre.openid.connect.model.UserInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.profile.common.BaseIntrospectionHelper;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcherRegistry;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.model.IamUserInfo;
import it.infn.mw.iam.persistence.repository.UserInfoAdapter;

public class IamJWTProfileTokenIntrospectionHelper extends BaseIntrospectionHelper {

  public static final Logger LOG =
      LoggerFactory.getLogger(IamJWTProfileTokenIntrospectionHelper.class);

  public IamJWTProfileTokenIntrospectionHelper(IamProperties props,
      IntrospectionResultAssembler assembler, ScopeMatcherRegistry registry) {
    super(props, assembler, registry);
  }


  @Override
  public Map<String, Object> assembleIntrospectionResult(OAuth2AccessTokenEntity accessToken,
      UserInfo userInfo, Set<String> authScopes) {

    Map<String, Object> result = getAssembler().assembleFrom(accessToken, userInfo, authScopes);

    addIssuerClaim(result);
    addAudience(result, accessToken);

    // Intersection of scopes authorized for the client and scopes linked to the
    // access token, using the scope matchers registry
    
    Set<String> scopes = filterScopes(accessToken, authScopes);
    
    addScopeClaim(result, scopes);

    if (userInfo != null) {
      if (scopes.contains(PROFILE)) {

        IamUserInfo iamUserInfo = ((UserInfoAdapter) userInfo).getUserinfo();

        if (!iamUserInfo.getGroups().isEmpty()) {

          result.put(GROUPS,
              iamUserInfo.getGroups().stream().map(IamGroup::getName).collect(Collectors.toList()));
        }

        result.put(NAME, iamUserInfo.getName());
        result.put(PREFERRED_USERNAME, iamUserInfo.getPreferredUsername());
        result.put(ORGANISATION_NAME, getProperties().getOrganisation().getName());
      }

      if (scopes.contains(EMAIL)) {
        result.put(EMAIL, userInfo.getEmail());
      }
    }

    return result;
  }

}
