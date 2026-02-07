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

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.SavedUserAuthentication;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.stereotype.Component;

import com.google.common.hash.Hashing;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.api.aup.AupService;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.scope.pdp.ScopeFilter;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamRevokedAccessToken;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;

@SuppressWarnings("deprecation")
@Component
public class TokenUtils {

  public static final Logger LOG = LoggerFactory.getLogger(IamTokenService.class);

  private final Clock clock;
  private final IamProperties iamProperties;
  private final IamOAuthAccessTokenRepository accessTokenRepo;
  private final IamAccountRepository accountRepository;
  private final IamClientRepository clientRepository;
  private final JWTSigningAndValidationService jwtSigningService;
  private final ScopeFilter scopeFilter;
  private final AupService aupService;

  public TokenUtils(Clock clock, IamProperties iamProperties,
      IamOAuthAccessTokenRepository accessTokenRepo, IamAccountRepository accountRepository,
      IamClientRepository clientRepository, JWTSigningAndValidationService jwtSigningService,
      ScopeFilter scopeFilter, AupService aupService) {

    this.clock = clock;
    this.iamProperties = iamProperties;
    this.accessTokenRepo = accessTokenRepo;
    this.accountRepository = accountRepository;
    this.clientRepository = clientRepository;
    this.jwtSigningService = jwtSigningService;
    this.scopeFilter = scopeFilter;
    this.aupService = aupService;
  }

  public ParsedAccessToken parseAccessToken(String accessToken) {

    try {
      SignedJWT jwt = SignedJWT.parse(accessToken);
      String issuer = jwt.getJWTClaimsSet().getIssuer();
      String sub = jwt.getJWTClaimsSet().getSubject();
      String clientId = jwt.getJWTClaimsSet().getStringClaim("client_id");
      Date expiration = jwt.getJWTClaimsSet().getExpirationTime();
      Set<String> scopes = Set.of(jwt.getJWTClaimsSet().getStringClaim("scope").split(" "));
      Set<String> audiences =
          jwt.getJWTClaimsSet().getAudience().stream().collect(Collectors.toSet());
      String refreshToken = jwt.getJWTClaimsSet().getStringClaim("refresh_token");
      Map<String, Object> external = jwt.getJWTClaimsSet().getJSONObjectClaim("external_authn");
      return new ParsedAccessToken(issuer, sub, clientId, expiration, scopes, audiences,
          jwt.getHeader(), jwt.getPayload(), jwt.getSignature(), jwt, refreshToken, external);
    } catch (ParseException e) {
      throw new InvalidTokenException("Token parsing error: " + e.getMessage());
    }
  }

  public OAuth2Authentication getAuthentication(ParsedAccessToken token) {

    if (token.isClient()) {
      return getClientAuthentication(token.clientId(), token.scopes(), token.audiences());
    }
    IamAccount account = accountRepository.findByUuid(token.sub())
      .orElseThrow(
          () -> new InvalidTokenException("User with subject " + token.sub() + " not found"));
    Set<SimpleGrantedAuthority> authorities = account.getAuthorities()
      .stream()
      .map(a -> new SimpleGrantedAuthority(a.getAuthority()))
      .collect(Collectors.toSet());
    Set<String> scopes = scopeFilter.filterScopes(token.scopes(), account);
    Authentication userAuthentication = buildAuthenticateUser(account, authorities);
    return getUserAuthentication(token.clientId(), scopes, authorities, token.audiences(),
        userAuthentication);
  }

  public void validate(ParsedAccessToken token) {

    validateSignature(token.jwt());
    validateIssuer(token.issuer());
    validateExpirationTime(token.expiration());
    validateClientId(token.clientId());
    if (!token.isClient()) {
      validateSub(token.sub());
    }
  }

  private void validateClientId(String clientId) {

    if (Objects.isNull(clientId)) {
      throw new InvalidTokenException("client_id claim not found on token");
    }
    ClientDetailsEntity client = clientRepository.findByClientId(clientId).orElseThrow();
    if (!client.isActive()) {
      throw new InvalidTokenException("Client with id " + clientId + " is not active");
    }
  }

  private void validateSignature(SignedJWT jwt) {

    if (jwt != null && jwt.getPayload() != null && !jwtSigningService.validateSignature(jwt)) {
      LOG.warn("Invalid signature for token {}", jwt.getPayload().toJSONObject());
      throw new InvalidTokenException("Invalid token signature");
    }
  }

  private void validateExpirationTime(Date expiration) {

    if (Objects.isNull(expiration)) {
      throw new InvalidTokenException("Access token exp claim is required");
    }
    Date now = Date.from(clock.instant());
    if (now.after(expiration)) {
      throw new InvalidTokenException("The access token is expired");
    }
  }

  private void validateIssuer(String issuer) {

    if (Objects.isNull(issuer) || !iamProperties.getIssuer().equals(issuer)) {
      throw new InvalidTokenException("Invalid access token issuer");
    }
  }

  private void validateSub(String uuid) {

    IamAccount account = accountRepository.findByUuid(uuid)
      .orElseThrow(() -> new InvalidTokenException("User with uuid " + uuid + " not found"));
    validateAccount(account);
  }

  private void validateAccount(IamAccount account) {

    if (!account.isActive()) {
      throw new InvalidTokenException("User " + account.getUsername() + " is not active");
    }
    if (account.getUserInfo().getEmailVerified() != null
        && !account.getUserInfo().getEmailVerified().booleanValue()) {
      throw new InvalidTokenException(
          "User " + account.getUsername() + " has a not verified email");
    }
    if (aupService.findAup().isPresent()) {
      // User test needs to sign AUP for this organization in order to proceed.
      if (account.getAupSignature() == null) {
        throw new InvalidTokenException("User " + account.getUsername()
            + " needs to sign AUP for this organization in order to proceed.");
      }
      if (!account.getAupSignature().getSignatureTime().toInstant().isBefore(clock.instant())) {
        throw new InvalidTokenException("User " + account.getUsername()
            + " needs to sign AUP for this organization in order to proceed.");
      }
    }
  }

  private void validateUser(String username) {

    IamAccount account = accountRepository.findByUsername(username)
      .orElseThrow(
          () -> new InvalidTokenException("User with username " + username + " not found"));
    validateAccount(account);
  }

  public IamRevokedAccessToken prepareRevocation(OAuth2AccessTokenEntity accessToken,
      Instant revokedAt) {

    IamRevokedAccessToken revoked = new IamRevokedAccessToken();
    revoked.setHashValue(accessToken.getTokenValueHash());
    revoked.setExpiration(accessToken.getExpiration());
    revoked.setRevokedAt(Date.from(revokedAt));
    return revoked;
  }

  public Authentication buildAuthenticateUser(IamAccount account,
      Set<SimpleGrantedAuthority> authorities) {

    SavedUserAuthentication auth = new SavedUserAuthentication();
    auth.setName(account.getUsername());
    auth.setAuthorities(authorities);
    auth.setAuthenticated(true);
    return auth;
  }

  private OAuth2Authentication getAuthentication(String clientId, Set<String> scopes,
      Set<SimpleGrantedAuthority> authorities, Set<String> audiences,
      Authentication userAuthentication) {

    return new OAuth2Authentication(new OAuth2Request(new HashMap<>(), clientId, authorities, true,
        scopes, audiences, null, null, null), userAuthentication);
  }

  public OAuth2Authentication getClientAuthentication(String clientId, Set<String> scopes,
      Set<String> audiences) {

    return getAuthentication(clientId, scopes, Set.of(new SimpleGrantedAuthority("ROLE_CLIENT")),
        audiences, null);
  }

  public OAuth2Authentication getUserAuthentication(String clientId, Set<String> scopes,
      Set<SimpleGrantedAuthority> authorities, Set<String> audiences,
      Authentication userAuthentication) {

    return getAuthentication(clientId, scopes, authorities, audiences, userAuthentication);
  }

  public Optional<OAuth2AccessTokenEntity> loadFromDatabase(String accessTokenValue) {

    Optional<OAuth2AccessTokenEntity> accessTokenOnDb =
        accessTokenRepo.findByTokenValue(sha256(accessTokenValue));

    if (accessTokenOnDb.isPresent()) {
      if (isExpired(accessTokenOnDb.get())) {
        throw new InvalidTokenException("The access token is expired");
      }
      return accessTokenOnDb;
    }
    if (iamProperties.getAccessToken().isStoreOnDatabase()) {
      throw new InvalidTokenException("Access token not found");
    }
    return Optional.empty();
  }

  public String sha256(String tokenString) {

    return Hashing.sha256().hashString(tokenString, StandardCharsets.UTF_8).toString();
  }

  public boolean isExpired(OAuth2AccessTokenEntity accessToken) {

    return !Objects.isNull(accessToken.getExpiration())
        && Date.from(clock.instant()).after(accessToken.getExpiration());
  }

  public void validate(OAuth2AccessTokenEntity token) {

    if (token.getExpiration() != null) {
      validateExpirationTime(token.getExpiration());
    }
    Authentication userAuth =
        token.getAuthenticationHolder().getAuthentication().getUserAuthentication();
    if (userAuth != null) {
      validateUser(userAuth.getName());
    }
  }
}
