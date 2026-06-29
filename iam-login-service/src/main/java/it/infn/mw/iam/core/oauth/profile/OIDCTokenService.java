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

import java.util.Date;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.springframework.security.oauth2.provider.OAuth2Request;

import com.nimbusds.jwt.JWT;

@SuppressWarnings("deprecation")
public interface OIDCTokenService {

  public JWT createIdToken(ClientDetailsEntity client, OAuth2Request request, Date issueTime,
      String sub, OAuth2AccessTokenEntity accessToken);

  public OAuth2AccessTokenEntity createRegistrationAccessToken(ClientDetailsEntity client);

  public OAuth2AccessTokenEntity createResourceAccessToken(ClientDetailsEntity client);

  public OAuth2AccessTokenEntity rotateRegistrationAccessTokenForClient(ClientDetailsEntity client);
}
