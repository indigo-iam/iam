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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;

import com.nimbusds.jwt.JWT;

import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.audit.events.tokens.RevocationEvent;
import it.infn.mw.iam.core.oauth.introspection.model.TokenTypeHint;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;

@Service
@Primary
public class IamTokenRevocationService implements TokenRevocationService {

  public static final Logger LOG = LoggerFactory.getLogger(IamTokenRevocationService.class);

  private final IamOAuthAccessTokenRepository accessTokenRepo;
  private final IamOAuthRefreshTokenRepository refreshTokenRepo;
  private final ClientService clientService;
  private final ApplicationEventPublisher eventPublisher;

  public IamTokenRevocationService(IamOAuthAccessTokenRepository accessTokenRepo,
      IamOAuthRefreshTokenRepository refreshTokenRepo, ClientService clientService,
      ApplicationEventPublisher eventPublisher) {

    this.accessTokenRepo = accessTokenRepo;
    this.refreshTokenRepo = refreshTokenRepo;
    this.clientService = clientService;
    this.eventPublisher = eventPublisher;
  }

  @Override
  public boolean isAccessTokenRevoked(OAuth2AccessTokenEntity token) {

    return accessTokenRepo.findByTokenValue(token.getTokenValueHash()).isEmpty();
  }

  @Override
  public boolean isRefreshTokenRevoked(OAuth2RefreshTokenEntity token) {

    return refreshTokenRepo.findByTokenValue(token.getJwt()).isEmpty();
  }

  @Override
  public void revokeAccessTokens(ClientDetailsEntity client) {

    accessTokenRepo.findAccessTokens(client.getId()).stream().forEach(this::revokeAccessToken);
  }

  @Override
  public void revokeRefreshTokens(ClientDetailsEntity client) {

    refreshTokenRepo.findByClientId(client.getId()).stream().forEach(this::revokeRefreshToken);
  }

  @Override
  public void revokeRegistrationToken(ClientDetailsEntity client) {

    accessTokenRepo.findRegistrationToken(client.getId()).ifPresent(this::revokeAccessToken);
  }

  @Override
  public void revokeAccessToken(OAuth2AccessTokenEntity at) {

    String jwtId = getJwtId(at.getJwt());
    if (at.isExpired()) {
      LOG.info("Refresh token (jti = {}) has expired. Revocation not necessary.", jwtId);
      accessTokenRepo.delete(at);
      return;
    }
    clientService.useClient(at.getClient());
    accessTokenRepo.delete(at);
    eventPublisher.publishEvent(new RevocationEvent(this, jwtId, TokenTypeHint.ACCESS_TOKEN));
  }

  @Override
  public void revokeRefreshToken(OAuth2RefreshTokenEntity rt) {

    /* Revoke all related Access Tokens */
    accessTokenRepo.findAccessTokensForRefreshToken(rt.getId()).forEach(this::revokeAccessToken);
    String jwtId = getJwtId(rt.getJwt());
    if (rt.isExpired()) {
      LOG.info("Refresh token (jti = {}) has expired. Revocation not necessary.", jwtId);
      refreshTokenRepo.delete(rt);
      return;
    }
    refreshTokenRepo.delete(rt);
    clientService.useClient(rt.getClient());
    eventPublisher.publishEvent(new RevocationEvent(this, jwtId, TokenTypeHint.REFRESH_TOKEN));
  }

  private String getJwtId(JWT jwt) {
    try {
      return jwt.getJWTClaimsSet().getJWTID();
    } catch (ParseException e) {
      throw new IllegalStateException("Unexpected JWT ParseException error: " + e.getMessage());
    }
  }
}
