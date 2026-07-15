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
import java.time.Clock;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;

import com.nimbusds.jwt.JWT;

import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.audit.events.tokens.RevocationEvent;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.TokenUtils;
import it.infn.mw.iam.core.oauth.introspection.model.TokenTypeHint;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamRevokedAccessToken;
import it.infn.mw.iam.persistence.model.OAuth2AccessTokenEntity;
import it.infn.mw.iam.persistence.model.OAuth2RefreshTokenEntity;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;
import it.infn.mw.iam.persistence.repository.IamRevokedAccessTokenRepository;

@Service
@Primary
public class IamTokenRevocationService implements TokenRevocationService {

  public static final Logger LOG = LoggerFactory.getLogger(IamTokenRevocationService.class);

  private final Clock clock;
  private final IamProperties iamProperties;
  private final IamOAuthAccessTokenRepository accessTokenRepo;
  private final IamOAuthRefreshTokenRepository refreshTokenRepo;
  private final IamRevokedAccessTokenRepository revokedAccessTokenRepo;
  private final ClientService clientService;
  private final ApplicationEventPublisher eventPublisher;
  private final TokenUtils tokenUtils;

  public IamTokenRevocationService(Clock clock, IamProperties iamProperties,
      IamOAuthAccessTokenRepository accessTokenRepo,
      IamOAuthRefreshTokenRepository refreshTokenRepo,
      IamRevokedAccessTokenRepository revokedAccessTokenRepo, ClientService clientService,
      ApplicationEventPublisher eventPublisher, TokenUtils tokenUtils) {

    this.clock = clock;
    this.iamProperties = iamProperties;
    this.accessTokenRepo = accessTokenRepo;
    this.refreshTokenRepo = refreshTokenRepo;
    this.revokedAccessTokenRepo = revokedAccessTokenRepo;
    this.clientService = clientService;
    this.eventPublisher = eventPublisher;
    this.tokenUtils = tokenUtils;
  }

  @Override
  public boolean isAccessTokenRevoked(String accessToken) {

    if (iamProperties.getAccessToken().isStoreOnDatabase()) {
      return accessTokenRepo.findByTokenValue(tokenUtils.sha256(accessToken)).isEmpty();
    }
    return revokedAccessTokenRepo.findByHashValue(tokenUtils.sha256(accessToken)).isPresent();
  }

  @Override
  public boolean isAccessTokenRevoked(OAuth2AccessTokenEntity accessToken) {

    if (iamProperties.getAccessToken().isStoreOnDatabase()) {
      return accessTokenRepo.findByTokenValue(accessToken.getTokenValueHash()).isEmpty();
    }
    return revokedAccessTokenRepo.findByHashValue(accessToken.getTokenValueHash()).isPresent();
  }

  @Override
  public boolean isRefreshTokenRevoked(OAuth2RefreshTokenEntity token) {

    return refreshTokenRepo.findByTokenValue(token.getValue()).isEmpty();
  }

  @Override
  public void revokeAccessTokens(ClientDetailsEntity client) {

    if (iamProperties.getAccessToken().isStoreOnDatabase()) {
      accessTokenRepo.findAccessTokens(client.getId()).stream().forEach(this::revokeAccessToken);
    }
  }

  @Override
  public void revokeRefreshTokens(ClientDetailsEntity client) {

    refreshTokenRepo.findByClientId(client.getId()).stream().forEach(this::revokeRefreshToken);
  }

  @Override
  public void revokeRegistrationToken(ClientDetailsEntity client) {

    accessTokenRepo.findRegistrationToken(client.getId()).ifPresent(this::revokeRegistrationToken);
  }

  @Override
  public void revokeRegistrationToken(OAuth2AccessTokenEntity registrationToken) {

    String hashValue = registrationToken.getTokenValueHash();
    accessTokenRepo.findByTokenValue(hashValue).ifPresent(regToken -> {
      LOG.debug("Deleting registration access token with hash {} from database", hashValue);
      accessTokenRepo.delete(regToken);
      clientService.useClient(regToken.getClient());
      eventPublisher.publishEvent(new RevocationEvent(this, hashValue, TokenTypeHint.ACCESS_TOKEN));
    });
  }

  @Override
  public void revokeAccessToken(OAuth2AccessTokenEntity accessToken) {

    String hashValue = accessToken.getTokenValueHash();
    LOG.debug("Revoking token with hash {}", hashValue);
    if (iamProperties.getAccessToken().isStoreOnDatabase()) {
      accessTokenRepo.findByTokenValue(hashValue).ifPresent(at -> {
        LOG.debug("Deleting token with hash {} from database", hashValue);
        accessTokenRepo.delete(at);
        clientService.useClient(accessToken.getClient());
        eventPublisher
          .publishEvent(new RevocationEvent(this, hashValue, TokenTypeHint.ACCESS_TOKEN));
      });
    } else {
      revokedAccessTokenRepo.findByHashValue(hashValue)
        .ifPresentOrElse(revoked -> LOG.debug("Token with hash {} already revoked at {}", hashValue,
            revoked.getRevokedAt()), () -> {
              IamRevokedAccessToken revoked =
                  tokenUtils.prepareRevocation(accessToken, clock.instant());
              LOG.debug("Prepared revocation entry {}", revoked);
              revokedAccessTokenRepo.save(revoked);
              clientService.useClient(accessToken.getClient());
              eventPublisher
                .publishEvent(new RevocationEvent(this, hashValue, TokenTypeHint.ACCESS_TOKEN));
            });
    }
  }

  @Override
  public void revokeRefreshToken(OAuth2RefreshTokenEntity rt) {

    refreshTokenRepo.findByTokenValue(rt.getValue()).ifPresent(token -> {
      refreshTokenRepo.delete(token);
      clientService.useClient(token.getClient());
      String jwtId = getJwtId(token.getJwt());
      eventPublisher.publishEvent(new RevocationEvent(this, jwtId, TokenTypeHint.REFRESH_TOKEN));
    });
  }

  private String getJwtId(JWT jwt) {
    try {
      return jwt.getJWTClaimsSet().getJWTID();
    } catch (ParseException e) {
      throw new IllegalStateException("Unexpected JWT ParseException error: " + e.getMessage());
    }
  }

  @Override
  public void revokeAccessTokens(IamAccount account) {

    if (iamProperties.getAccessToken().isStoreOnDatabase()) {
      accessTokenRepo.findAccessTokensForUser(account.getUsername())
        .forEach(this::revokeAccessToken);
    }
  }

  @Override
  public void revokeRefreshTokens(IamAccount account) {

    refreshTokenRepo.findRefreshTokensForUser(account.getUsername())
      .forEach(this::revokeRefreshToken);
  }
}
