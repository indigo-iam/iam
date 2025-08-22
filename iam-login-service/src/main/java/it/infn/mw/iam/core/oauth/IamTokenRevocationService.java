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

import static it.infn.mw.iam.core.IamTokenService.sha256;

import java.text.ParseException;
import java.util.Date;
import java.util.Optional;

import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.stereotype.Service;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.introspection.model.TokenTypeHint;
import it.infn.mw.iam.persistence.model.IamRevokedAccessToken;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;
import it.infn.mw.iam.persistence.repository.IamRevokedAccessTokenRepository;

@SuppressWarnings("deprecation")
@Service
public class IamTokenRevocationService implements TokenRevocationService {

  public static final String CACHE_KEY = "token-revocation-list";

  private final IamOAuthAccessTokenRepository accessTokenRepo;
  private final IamRevokedAccessTokenRepository revokedAccessTokenRepo;
  private final IamOAuthRefreshTokenRepository refreshTokenRepo;
  private final boolean isAccessTokenStoredOnDatabase;

  public IamTokenRevocationService(IamOAuthAccessTokenRepository accessTokenRepo,
      IamRevokedAccessTokenRepository revokedAccessTokenRepo,
      IamOAuthRefreshTokenRepository refreshTokenRepo, IamProperties properties) {

    this.accessTokenRepo = accessTokenRepo;
    this.revokedAccessTokenRepo = revokedAccessTokenRepo;
    this.refreshTokenRepo = refreshTokenRepo;
    this.isAccessTokenStoredOnDatabase = properties.getAccessToken().isStoreOnDatabase();
  }

  @Override
  @Cacheable(value = CACHE_KEY, key = "#token")
  public boolean isTokenRevoked(JWT token, TokenTypeHint tokenType) throws ParseException {

    switch (tokenType) {
      case REFRESH_TOKEN:
        return isRefreshTokenRevoked((PlainJWT) token);
      case REGISTRATION_ACCESS_TOKEN:
      case RESOURCE_ACCESS_TOKEN:
        return isAccessTokenOnDatabaseRevoked((SignedJWT) token);
      default:
        return isAccessTokenRevoked((SignedJWT) token);
    }
  }

  @Override
  @CacheEvict(value = CACHE_KEY, key = "#token")
  public void revokeToken(JWT token, TokenTypeHint tokenType) throws ParseException {

    if (!validate(token, tokenType)) {
      return;
    }

    switch (tokenType) {
      case REFRESH_TOKEN:
        revokeRefreshToken((PlainJWT) token);
        break;
      case REGISTRATION_ACCESS_TOKEN:
      case RESOURCE_ACCESS_TOKEN:
        revokeAccessTokenOnDatabase((SignedJWT) token);
      default:
        revokeAccessToken((SignedJWT) token);
        break;
    }
  }

  private boolean validate(JWT token, TokenTypeHint tokenType) throws ParseException {

    if (token == null || tokenType == null) {
      return false;
    }
    /* check if the provided token type matches the expected type computed from JWT */
    TokenTypeHint computedTokenType = TokenTypeHint.valueFrom(token);
    return tokenType.equals(computedTokenType) && !isTokenExpired(token);
  }

  private boolean isTokenExpired(JWT jwt) throws ParseException {

    Optional<Date> expClaim = Optional.ofNullable(jwt.getJWTClaimsSet().getDateClaim("exp"));
    return expClaim.isPresent() && expClaim.get().before(new Date());
  }

  private boolean isAccessTokenRevoked(SignedJWT jwt) throws InvalidTokenException, ParseException {

    if (isAccessTokenStoredOnDatabase) {
      return isAccessTokenOnDatabaseRevoked(jwt);
    }
    String jtiClaim = jwt.getJWTClaimsSet().getJWTID();
    if (jtiClaim == null || jtiClaim.isBlank()) {
      throw new InvalidTokenException("Missing or blank jti from token");
    }
    return revokedAccessTokenRepo.findById(jtiClaim).isPresent();
  }

  private void revokeAccessToken(SignedJWT jwt) throws ParseException {

    if (isAccessTokenStoredOnDatabase) {
      revokeAccessTokenOnDatabase(jwt);
    } else {
      IamRevokedAccessToken revoked = new IamRevokedAccessToken();
      revoked.setJti(jwt.getJWTClaimsSet().getJWTID());
      revoked.setExpiration(jwt.getJWTClaimsSet().getExpirationTime());
      revokedAccessTokenRepo.save(revoked);
    }
  }

  private boolean isAccessTokenOnDatabaseRevoked(SignedJWT jwt) throws ParseException {

    return accessTokenRepo.findByTokenValue(sha256(jwt.serialize())).isEmpty();
  }

  private void revokeAccessTokenOnDatabase(SignedJWT jwt) throws ParseException {

    accessTokenRepo.findByTokenValue(sha256(jwt.serialize())).ifPresent(accessTokenRepo::delete);
  }

  private boolean isRefreshTokenRevoked(PlainJWT jwt) {

    return refreshTokenRepo.findByTokenValue(jwt).isEmpty();
  }

  private void revokeRefreshToken(PlainJWT jwt) {

    refreshTokenRepo.findByTokenValue(jwt).ifPresent(refreshTokenRepo::delete);
  }

}
