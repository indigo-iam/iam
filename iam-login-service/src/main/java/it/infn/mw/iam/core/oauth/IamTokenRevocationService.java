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

import java.text.ParseException;
import java.util.Optional;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.stereotype.Service;

import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.core.oauth.exceptions.ClientNotAllowed;
import it.infn.mw.iam.persistence.model.IamRevokedAccessToken;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;
import it.infn.mw.iam.persistence.repository.IamRevokedAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;

@SuppressWarnings("deprecation")
@Service
public class IamTokenRevocationService implements TokenRevocationService {

  public static final String CACHE_KEY = "token-revocation-list";

  private final IamRevokedAccessTokenRepository revokedAccessTokenRepo;
  private final IamOAuthRefreshTokenRepository refreshTokenRepo;
  private final IamClientRepository clientRepository;

  public IamTokenRevocationService(IamRevokedAccessTokenRepository revokedAccessTokenRepo,
      IamOAuthRefreshTokenRepository refreshTokenRepo, IamClientRepository clientRepository) {
    this.revokedAccessTokenRepo = revokedAccessTokenRepo;
    this.refreshTokenRepo = refreshTokenRepo;
    this.clientRepository = clientRepository;
  }

  @Cacheable(value = CACHE_KEY, key = "#token")
  public boolean isAccessTokenRevoked(String token) {
    try {
      SignedJWT jwt = SignedJWT.parse(token);
      return revokedAccessTokenRepo.findById(jwt.getJWTClaimsSet().getJWTID()).isPresent();
    } catch (Exception e) {
      throw new InvalidTokenException(e.getMessage());
    }
  }

  @Override
  @CacheEvict(cacheNames = CACHE_KEY, key = "#token")
  public void revokeAccessToken(String clientId, String token)
      throws ClientNotAllowed {

    try {
      SignedJWT jwt = SignedJWT.parse(token);
      validate(clientId, jwt);
      IamRevokedAccessToken revoked = new IamRevokedAccessToken();
      revoked.setJit(jwt.getJWTClaimsSet().getJWTID());
      revoked.setExp(jwt.getJWTClaimsSet().getExpirationTime());
      revokedAccessTokenRepo.save(revoked);
    } catch (InvalidTokenException | ParseException e) {
      /*
       * Note: invalid tokens do not cause an error response since the client cannot handle such an
       * error in a reasonable way. Source:
       * https://datatracker.ietf.org/doc/html/rfc7009#section-2.2
       * 
       */
    }
  }

  @Override
  public void revokeRefreshToken(String clientId, String token)
      throws ClientNotAllowed {

    PlainJWT jwt = null;
    try {
      jwt = PlainJWT.parse(token);
    } catch (ParseException e) {
      /*
       * Note: invalid tokens do not cause an error response since the client cannot handle such an
       * error in a reasonable way. Source:
       * https://datatracker.ietf.org/doc/html/rfc7009#section-2.2
       * 
       */
      return;
    }
    Optional<OAuth2RefreshTokenEntity> rt = refreshTokenRepo.findByTokenValue(jwt);
    if (rt.isPresent()) {
      validate(clientId, rt.get());
      refreshTokenRepo.delete(rt.get());
    }
  }

  private void validate(String clientId, SignedJWT jwt)
      throws ParseException, ClientNotAllowed {

    Optional<Object> clientIdClaim =
        Optional.ofNullable(jwt.getJWTClaimsSet().getClaim("client_id"));
    if (clientIdClaim.isEmpty()) {
      throw new InvalidTokenException("Claim client_id not found in token");
    }

    ClientDetailsEntity client = clientRepository.findByClientId(clientId)
      .orElseThrow(() -> new InvalidTokenException("Invalid token's client_id " + clientId));

    if (!client.getClientId().equals(String.valueOf(clientIdClaim.get()))) {
      throw new ClientNotAllowed("Client is not allowed to revoke this token");
    }
  }

  private void validate(String clientId, OAuth2RefreshTokenEntity rt) throws ClientNotAllowed {

    if (!clientId.equals(rt.getClient().getClientId())) {
      throw new ClientNotAllowed("Client is not allowed to revoke this token");
    }
  }

}
