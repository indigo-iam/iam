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
package it.infn.mw.iam.core;

import java.util.Date;
import java.util.List;
import java.util.Set;

import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;

import com.nimbusds.jwt.JWT;

import it.infn.mw.iam.persistence.model.AuthenticationHolderEntity;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.model.OAuth2AccessTokenEntity;
import it.infn.mw.iam.persistence.model.OAuth2RefreshTokenEntity;

@SuppressWarnings("deprecation")
public interface OAuth2TokenEntityService
    extends AuthorizationServerTokenServices, ResourceServerTokenServices {

  @Override
  public OAuth2AccessTokenEntity readAccessToken(String accessTokenValue);

  @Override
  public OAuth2AccessTokenEntity getAccessToken(OAuth2Authentication authentication);

  public OAuth2RefreshTokenEntity getRefreshToken(String refreshTokenValue);

//  public void revokeRefreshToken(OAuth2RefreshTokenEntity refreshToken);

//  public void revokeAccessToken(OAuth2AccessTokenEntity accessToken);

  public List<OAuth2AccessTokenEntity> getAccessTokensForClient(ClientDetailsEntity client);

  public List<OAuth2RefreshTokenEntity> getRefreshTokensForClient(ClientDetailsEntity client);

  public OAuth2AccessTokenEntity getAccessTokenById(Long id);

  public OAuth2RefreshTokenEntity getRefreshTokenById(Long id);

  public Set<OAuth2AccessTokenEntity> getAllAccessTokensForUser(String name);

  public Set<OAuth2RefreshTokenEntity> getAllRefreshTokensForUser(String name);

//  public OAuth2AccessTokenEntity getRegistrationAccessTokenForClient(ClientDetailsEntity client);

  public JWT createIdToken(ClientDetailsEntity client, OAuth2Request request, Date issueTime,
      String sub, OAuth2AccessTokenEntity accessToken);

  public OAuth2AccessTokenEntity createRegistrationAccessToken(ClientDetailsEntity client);

  public OAuth2AccessTokenEntity createResourceAccessToken(ClientDetailsEntity client);

  public OAuth2AccessTokenEntity rotateRegistrationAccessTokenForClient(ClientDetailsEntity client);

  public OAuth2AccessTokenEntity rotateResourceAccessTokenForClient(ClientDetailsEntity client);

}
