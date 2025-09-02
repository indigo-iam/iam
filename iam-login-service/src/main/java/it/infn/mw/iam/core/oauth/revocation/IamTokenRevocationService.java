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

import org.springframework.stereotype.Service;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.core.oauth.introspection.model.TokenTypeHint;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;

@Service
public class IamTokenRevocationService implements TokenRevocationService {

  private final IamOAuthAccessTokenRepository accessTokenRepo;
  private final IamOAuthRefreshTokenRepository refreshTokenRepo;

  public IamTokenRevocationService(IamOAuthAccessTokenRepository accessTokenRepo,
      IamOAuthRefreshTokenRepository refreshTokenRepo) {

    this.accessTokenRepo = accessTokenRepo;
    this.refreshTokenRepo = refreshTokenRepo;
  }

  @Override
  public boolean isTokenRevoked(JWT token, TokenTypeHint tokenType) throws ParseException {

    switch (tokenType) {
      case REFRESH_TOKEN:
        return isRefreshTokenRevoked((PlainJWT) token);
      default:
        return isAccessTokenRevoked((SignedJWT) token);
    }
  }

  @Override
  public void revokeToken(JWT token, TokenTypeHint tokenType) throws ParseException {

    if (!validate(token, tokenType)) {
      return;
    }
    switch (tokenType) {
      case REFRESH_TOKEN:
        revokeRefreshToken((PlainJWT) token);
        break;
      default:
        revokeAccessToken((SignedJWT) token);
        break;
    }
  }

  private boolean validate(JWT token, TokenTypeHint tokenType) throws ParseException {

    return token != null && tokenType != null && !isTokenExpired(token);
  }

  private boolean isTokenExpired(JWT jwt) throws ParseException {

    Optional<Date> expClaim = Optional.ofNullable(jwt.getJWTClaimsSet().getDateClaim("exp"));
    return expClaim.isPresent() && expClaim.get().before(new Date());
  }

  private boolean isAccessTokenRevoked(SignedJWT jwt) throws ParseException {

    return accessTokenRepo.findByTokenValue(sha256(jwt.serialize())).isEmpty();
  }

  private void revokeAccessToken(SignedJWT jwt) throws ParseException {

    accessTokenRepo.findByTokenValue(sha256(jwt.serialize())).ifPresent(accessTokenRepo::delete);
  }

  private boolean isRefreshTokenRevoked(PlainJWT jwt) {

    return refreshTokenRepo.findByTokenValue(jwt).isEmpty();
  }

  private void revokeRefreshToken(PlainJWT jwt) {

    refreshTokenRepo.findByTokenValue(jwt).ifPresent(refreshTokenRepo::delete);
  }

}