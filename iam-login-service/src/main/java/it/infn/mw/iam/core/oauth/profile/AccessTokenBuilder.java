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
package it.infn.mw.iam.core.oauth.profile;

import java.time.Instant;
import java.util.Set;

import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.openid.connect.model.UserInfo;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import com.nimbusds.jwt.JWTClaimsSet;

@SuppressWarnings("deprecation")
public interface AccessTokenBuilder {

  /**
   * The list of claims returned if authentication info are required to be included
   * in access tokens
   * 
   * @return the Set of claims required when authentication info are included in
   * access tokens
   */
  Set<String> getAdditionalAuthnInfoClaims();

  /**
   * Return the claim Set of the access token
   * 
   * @param token
   * @param authentication
   * @param userInfo
   * @param issueTime
   * @return the claim Set of the access token
   */
  JWTClaimsSet buildAccessToken(OAuth2AccessTokenEntity token, OAuth2Authentication authentication,
      UserInfo userInfo, Instant issueTime);
}
