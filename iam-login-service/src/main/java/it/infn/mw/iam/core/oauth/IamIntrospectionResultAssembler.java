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
package it.infn.mw.iam.core.oauth;

import static com.google.common.collect.Maps.newLinkedHashMap;

import java.text.ParseException;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import com.google.common.base.Joiner;
import com.google.common.collect.Sets;

import it.infn.mw.iam.authn.oidc.model.UserInfo;
import it.infn.mw.iam.core.IamTokenService;
import it.infn.mw.iam.core.oauth.profile.JWTProfile;
import it.infn.mw.iam.core.oauth.profile.JWTProfileResolver;
import it.infn.mw.iam.core.oauth.service.IntrospectionResultAssembler;
import it.infn.mw.iam.persistence.model.IamAccessToken;
import it.infn.mw.iam.persistence.model.IamRefreshToken;

@SuppressWarnings("deprecation")
public class IamIntrospectionResultAssembler implements IntrospectionResultAssembler {

  public static final Logger LOG = LoggerFactory.getLogger(IamTokenService.class);

  private final JWTProfileResolver profileResolver;

  public IamIntrospectionResultAssembler(JWTProfileResolver profileResolver) {
    this.profileResolver = profileResolver;
  }

  @Override
  public Map<String, Object> assembleFrom(IamAccessToken accessToken, UserInfo userInfo,
      Set<String> authScopes) {

    JWTProfile profile = profileResolver.resolveProfile(accessToken.getClient().getClientId());
    return profile.getIntrospectionResultHelper()
      .assembleIntrospectionResult(accessToken, userInfo, authScopes);
  }

  @Override
  public Map<String, Object> assembleFrom(IamRefreshToken refreshToken, UserInfo userInfo, Set<String> authScopes) {

      Map<String, Object> result = newLinkedHashMap();
      OAuth2Authentication authentication = refreshToken.getAuthenticationHolder().getAuthentication();

      result.put(ACTIVE, true);

      Set<String> scopes = Sets.intersection(authScopes, authentication.getOAuth2Request().getScope());

      result.put(SCOPE, Joiner.on(SCOPE_SEPARATOR).join(scopes));

      if (refreshToken.getExpiration() != null) {
          try {
              result.put(EXPIRES_AT, dateFormat.valueToString(refreshToken.getExpiration()));
              result.put(EXP, refreshToken.getExpiration().getTime() / 1000L);
          } catch (ParseException e) {
              LOG.error("Parse exception in token introspection", e);
          }
      }

      if (userInfo != null) {
          // if we have a UserInfo, use that for the subject
          result.put(SUB, userInfo.getSub());
      } else {
          // otherwise, use the authentication's username
          result.put(SUB, authentication.getName());
      }

      if(authentication.getUserAuthentication() != null) {
          result.put(USER_ID, authentication.getUserAuthentication().getName());
      }

      result.put(CLIENT_ID, authentication.getOAuth2Request().getClientId());

      return result;
  }
}
