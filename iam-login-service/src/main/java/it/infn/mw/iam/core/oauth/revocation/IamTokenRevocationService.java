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

import static it.infn.mw.iam.core.IamTokenService.sha256;

import java.text.ParseException;
import java.util.Date;
import java.util.Optional;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.stereotype.Service;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.audit.events.tokens.RevocationEvent;
import it.infn.mw.iam.core.oauth.introspection.model.TokenTypeHint;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;

@Service
public class IamTokenRevocationService
    implements TokenRevocationService, ApplicationEventPublisherAware {

  private final IamOAuthAccessTokenRepository accessTokenRepo;
  private final IamOAuthRefreshTokenRepository refreshTokenRepo;
  private ApplicationEventPublisher eventPublisher;

  public IamTokenRevocationService(IamOAuthAccessTokenRepository accessTokenRepo,
      IamOAuthRefreshTokenRepository refreshTokenRepo) {

    this.accessTokenRepo = accessTokenRepo;
    this.refreshTokenRepo = refreshTokenRepo;
  }

  @Override
  public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
    this.eventPublisher = applicationEventPublisher;
  }

  private boolean isTokenExpired(JWT jwt) throws ParseException {

    Optional<Date> expClaim = Optional.ofNullable(jwt.getJWTClaimsSet().getDateClaim("exp"));
    return expClaim.isPresent() && expClaim.get().before(new Date());
  }

  @Override
  public boolean isAccessTokenRevoked(SignedJWT token) {

    return accessTokenRepo.findByTokenValue(sha256(token.serialize())).isEmpty();
  }

  @Override
  public boolean isRefreshTokenRevoked(PlainJWT token) {

    return refreshTokenRepo.findByTokenValue(token).isEmpty();
  }

  @Override
  public void revokeAccessToken(SignedJWT token) throws ParseException {

    if (isTokenExpired(token)) {
      return;
    }
    accessTokenRepo.findByTokenValue(sha256(token.serialize())).ifPresent(at -> {
      accessTokenRepo.delete(at);
      eventPublisher.publishEvent(
          new RevocationEvent(this, at.getJwt().serialize(), TokenTypeHint.ACCESS_TOKEN));
    });
  }

  @Override
  public void revokeRefreshToken(PlainJWT token) throws ParseException {

    if (isTokenExpired(token)) {
      return;
    }
    refreshTokenRepo.findByTokenValue(token).ifPresent(rt -> {
      refreshTokenRepo.delete(rt);
      eventPublisher.publishEvent(
          new RevocationEvent(this, rt.getJwt().serialize(), TokenTypeHint.REFRESH_TOKEN));
    });
  }

}
