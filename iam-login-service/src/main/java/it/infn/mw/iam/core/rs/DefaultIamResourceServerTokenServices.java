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
package it.infn.mw.iam.core.rs;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.core.ParsedAccessToken;
import it.infn.mw.iam.core.TokenUtils;
import it.infn.mw.iam.core.oauth.revocation.TokenRevocationService;

@SuppressWarnings("deprecation")
@Service
public class DefaultIamResourceServerTokenServices implements ResourceServerTokenServices {

  private final ClientService clientService;
  private final TokenRevocationService revocationService;
  private final TokenUtils tokenUtils;

  public DefaultIamResourceServerTokenServices(ClientService clientService,
      TokenRevocationService revocationService, TokenUtils tokenUtils) {
    this.clientService = clientService;
    this.revocationService = revocationService;
    this.tokenUtils = tokenUtils;
  }

  @Override
  public OAuth2Authentication loadAuthentication(String accessTokenValue)
      throws AuthenticationException {

    Optional<OAuth2AccessTokenEntity> accessTokenOnDb =
        tokenUtils.loadFromDatabase(accessTokenValue);
    if (accessTokenOnDb.isPresent()) {
      tokenUtils.validate(accessTokenOnDb.get());
      return accessTokenOnDb.get().getAuthenticationHolder().getAuthentication();
    }
    if (revocationService.isAccessTokenRevoked(accessTokenValue)) {
      throw new InvalidTokenException("The access token has been revoked");
    }
    ParsedAccessToken token = parseAndValidate(accessTokenValue);
    return tokenUtils.getAuthentication(token);
  }

  @Override
  public OAuth2AccessTokenEntity readAccessToken(String accessTokenValue) {

    Optional<OAuth2AccessTokenEntity> accessTokenOnDb =
        tokenUtils.loadFromDatabase(accessTokenValue);
    if (accessTokenOnDb.isPresent()) {
      return accessTokenOnDb.get();
    }
    if (revocationService.isAccessTokenRevoked(accessTokenValue)) {
      throw new InvalidTokenException("The access token has been revoked");
    }
    return buildAccessToken(parseAndValidate(accessTokenValue));
  }

  private ParsedAccessToken parseAndValidate(String accessTokenValue) {

    ParsedAccessToken token = tokenUtils.parseAccessToken(accessTokenValue);
    tokenUtils.validate(token);
    return token;
  }

  private OAuth2AccessTokenEntity buildAccessToken(ParsedAccessToken accessToken) {

    OAuth2AccessTokenEntity entity = new OAuth2AccessTokenEntity();
    entity.setJwt(accessToken.jwt());
    entity.setExpiration(accessToken.expiration());
    entity.setScope(accessToken.scopes());
    entity.setTokenType(OAuth2AccessToken.BEARER_TYPE);
    if (!Objects.isNull(accessToken.refreshToken())) {
      OAuth2RefreshToken refreshToken = new DefaultOAuth2RefreshToken(accessToken.refreshToken());
      entity.setRefreshToken(refreshToken);
    }
    entity.setTokenValueHash(tokenUtils.sha256(accessToken.jwt().serialize()));
    entity.setClient(loadClient(accessToken.clientId()));
    entity.getAdditionalInformation().clear();
    List<String> notAllowed = List.of("scope", "exp");
    entity.getAdditionalInformation().putAll(accessToken.payload().toJSONObject());
    entity.getAdditionalInformation().keySet().removeIf(notAllowed::contains);
    return entity;
  }

  private ClientDetailsEntity loadClient(String clientId) {

    return clientService.findClientByClientId(clientId)
      .orElseThrow(() -> new InvalidTokenException("Client not found with client id " + clientId));
  }
}
