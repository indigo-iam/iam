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
package it.infn.mw.iam.core.oauth.revocation;

import java.text.ParseException;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;

public interface TokenRevocationService {

  public boolean isAccessTokenRevoked(OAuth2AccessTokenEntity token) throws ParseException;

  public boolean isRefreshTokenRevoked(OAuth2RefreshTokenEntity token) throws ParseException;

  public void revokeAccessToken(OAuth2AccessTokenEntity token);

  public void revokeRefreshToken(OAuth2RefreshTokenEntity token);

  public void revokeAccessTokens(ClientDetailsEntity client);

  public void revokeRegistrationToken(ClientDetailsEntity client);

  public void revokeRefreshTokens(ClientDetailsEntity client);

}