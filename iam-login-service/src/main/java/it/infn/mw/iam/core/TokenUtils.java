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
import java.time.Duration;
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
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.api.aup.AupService;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.scope.pdp.ScopeFilter;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAup;
import it.infn.mw.iam.persistence.model.IamRevokedAccessToken;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;

@SuppressWarnings("deprecation")
@Component
public class TokenUtils {

  public static final Logger LOG = LoggerFactory.getLogger(TokenUtils.class);

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
      JWTClaimsSet claims = jwt.getJWTClaimsSet();
      String issuer = claims.getIssuer();
      String sub = claims.getSubject();
      String clientId = claims.getStringClaim("client_id");
      Date expiration = claims.getExpirationTime();
      String scopeClaim = claims.getStringClaim("scope");
      Set<String> scopeSet = scopeClaim == null ? Set.of() : Set.of(scopeClaim.split(" "));
      Set<String> audiences = claims.getAudience().stream().collect(Collectors.toSet());
      String refreshToken = claims.getStringClaim("refresh_token");
      Map<String, Object> external = claims.getJSONObjectClaim("external_authn");
      return new ParsedAccessToken(issuer, sub, clientId, expiration, scopeSet, audiences,
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

    validateSignature(token);
    validateIssuer(token);
    validateExpiration(token);
    validateClientId(token);
    validateScopes(token);
    if (!token.isClient()) {
      validateSub(token);
    }
  }

  private void validateClientId(ParsedAccessToken token) {

    if (Objects.isNull(token.clientId())) {
      throw new InvalidTokenException("client_id claim not found on token");
    }
    ClientDetailsEntity client = clientRepository.findByClientId(token.clientId()).orElseThrow();
    if (!client.isActive()) {
      throw new InvalidTokenException("Client with id " + token.clientId() + " is not active");
    }
  }

  private void validateScopes(ParsedAccessToken token) {

    if (token.scopes() == null || token.scopes().isEmpty()) {
      throw new InvalidTokenException("missing or empty scope claim");
    }
  }

  private void validateSignature(ParsedAccessToken token) {

    Objects.requireNonNull(token.jwt());
    Objects.requireNonNull(token.jwt().getPayload());
    if (!jwtSigningService.validateSignature(token.jwt())) {
      LOG.warn("Invalid signature for token {}", token.jwt().getPayload().toJSONObject());
      throw new InvalidTokenException("Invalid token signature");
    }
    LOG.debug("Valid signature for token {}", token.jwt().getPayload().toJSONObject());
  }

  private void validateExpiration(Date exp) {
    if (Objects.isNull(exp)) {
      throw new InvalidTokenException("Access token exp claim is required");
    }
    if (Date.from(clock.instant()).after(exp)) {
      throw new InvalidTokenException("The access token is expired");
    }
  }

  private void validateExpiration(ParsedAccessToken token) {

    validateExpiration(token.expiration());
  }

  private void validateExpiration(OAuth2AccessTokenEntity token) {

    validateExpiration(token.getExpiration());
  }

  private void validateIssuer(ParsedAccessToken token) {

    if (Objects.isNull(token.issuer()) || !iamProperties.getIssuer().equals(token.issuer())) {
      throw new InvalidTokenException("Invalid access token issuer");
    }
  }

  private void validateSub(ParsedAccessToken token) {

    IamAccount account = accountRepository.findByUuid(token.sub())
      .orElseThrow(() -> new InvalidTokenException("User with uuid " + token.sub() + " not found"));
    validateAccount(account);
  }

  private void validateAccount(IamAccount account) {

    if (!account.isActive()) {
      throw new InvalidTokenException("User with uuid " + account.getUuid() + " is not active");
    }
    if (account.getUserInfo().getEmailVerified() != null
        && !account.getUserInfo().getEmailVerified().booleanValue()) {
      throw new InvalidTokenException(
          "User with uuid " + account.getUuid() + " has a not verified email");
    }
    Optional<IamAup> aup = aupService.findAup();
    if (aup.isPresent()) {
      // User test needs to sign AUP for this organization in order to proceed.
      if (account.getAupSignature() == null) {
        throw new InvalidTokenException("User with uuid " + account.getUuid()
            + " needs to sign AUP for this organization in order to proceed.");
      }
      Instant signatureExpiration = account.getAupSignature()
        .getSignatureTime()
        .toInstant()
        .plus(Duration.ofDays(aup.get().getSignatureValidityInDays()));
      if (signatureExpiration.isBefore(clock.instant())) {
        throw new InvalidTokenException("User with uuid " + account.getUuid()
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
      ParsedAccessToken token = parseAccessToken(accessTokenValue);
      if (isExpired(token)) {
        throw new InvalidTokenException("The access token is expired");
      }
      throw new InvalidTokenException("Access token not found");
    }
    return Optional.empty();
  }

  public String sha256(String tokenString) {

    return Hashing.sha256().hashString(tokenString, StandardCharsets.UTF_8).toString();
  }

  public boolean isExpired(ParsedAccessToken accessToken) {

    return isExpired(accessToken.expiration());
  }

  public boolean isExpired(OAuth2AccessTokenEntity accessToken) {

    return isExpired(accessToken.getExpiration());
  }

  public boolean isExpired(Date exp) {

    return exp != null && Date.from(clock.instant()).after(exp);
  }

  public void validate(OAuth2AccessTokenEntity token) {

    if (token.getExpiration() != null) {
      validateExpiration(token);
    }
    Authentication userAuth =
        token.getAuthenticationHolder().getAuthentication().getUserAuthentication();
    if (userAuth != null) {
      validateUser(userAuth.getName());
    }
  }
}
