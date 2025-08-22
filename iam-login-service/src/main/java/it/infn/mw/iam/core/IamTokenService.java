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

import static java.lang.String.valueOf;
import static org.mitre.oauth2.service.SystemScopeService.REGISTRATION_TOKEN_SCOPE;
import static org.mitre.oauth2.service.SystemScopeService.RESOURCE_TOKEN_SCOPE;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.LocalDate;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import javax.transaction.Transactional;

import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mitre.oauth2.model.AuthenticationHolderEntity;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.ClientLastUsedEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.mitre.oauth2.model.SavedUserAuthentication;
import org.mitre.oauth2.service.impl.DefaultOAuth2ProviderTokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Primary;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.stereotype.Service;

import com.google.common.collect.Sets;
import com.google.common.hash.Hashing;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.audit.events.tokens.AccessTokenIssuedEvent;
import it.infn.mw.iam.audit.events.tokens.RefreshTokenIssuedEvent;
import it.infn.mw.iam.authn.util.Authorities;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.TokenRevocationService;
import it.infn.mw.iam.core.oauth.introspection.model.TokenTypeHint;
import it.infn.mw.iam.core.oauth.scope.pdp.ScopeFilter;
import it.infn.mw.iam.core.oauth.tokens.JwtToOAuth2AccessTokenConverter;
import it.infn.mw.iam.core.oauth.tokens.OAuthTokenClaims;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;

@SuppressWarnings("deprecation")
@Service("defaultOAuth2ProviderTokenService")
@Primary
public class IamTokenService extends DefaultOAuth2ProviderTokenService {

  public static final Logger LOG = LoggerFactory.getLogger(IamTokenService.class);

  private final IamOAuthAccessTokenRepository accessTokenRepo;
  private final IamOAuthRefreshTokenRepository refreshTokenRepo;
  private final IamClientRepository clientRepo;
  private final IamAccountRepository accountRepository;
  private final ApplicationEventPublisher eventPublisher;
  private final ScopeFilter scopeFilter;
  private final JwtToOAuth2AccessTokenConverter jwtConverter;
  private final JWTSigningAndValidationService jwtSigningService;
  private final TokenRevocationService revocationService;

  private boolean isTrackLastUsed;
  private boolean isAccessTokenOnDatabase;

  public IamTokenService(IamOAuthAccessTokenRepository accessTokenRepo,
      IamOAuthRefreshTokenRepository refreshTokenRepo, IamClientRepository clientRepo,
      IamAccountRepository accountRepository,
      ApplicationEventPublisher eventPublisher, IamProperties iamProperties,
      ScopeFilter scopeFilter, JwtToOAuth2AccessTokenConverter jwtConverter,
      JWTSigningAndValidationService jwtSigningService,
      TokenRevocationService revocationService) {

    this.accessTokenRepo = accessTokenRepo;
    this.refreshTokenRepo = refreshTokenRepo;
    this.clientRepo = clientRepo;
    this.accountRepository = accountRepository;
    this.eventPublisher = eventPublisher;
    this.scopeFilter = scopeFilter;
    this.jwtConverter = jwtConverter;
    this.jwtSigningService = jwtSigningService;
    this.revocationService = revocationService;

    this.isTrackLastUsed = iamProperties.getClient().isTrackLastUsed();
    this.isAccessTokenOnDatabase = iamProperties.getAccessToken().isStoreOnDatabase();
  }

  public boolean isTrackLastUsed() {
    return isTrackLastUsed;
  }

  public void setTrackLastUsed(boolean isTrackLastUsed) {
    this.isTrackLastUsed = isTrackLastUsed;
  }

  public boolean isAccessTokenOnDatabase() {
    return isAccessTokenOnDatabase;
  }

  public void setAccessTokenOnDatabase(boolean isAccessTokenOnDatabase) {
    this.isAccessTokenOnDatabase = isAccessTokenOnDatabase;
  }

  @Override
  public Set<OAuth2AccessTokenEntity> getAllAccessTokensForUser(String id) {

    if (isAccessTokenOnDatabase) {
      Set<OAuth2AccessTokenEntity> results = Sets.newLinkedHashSet();
      results.addAll(accessTokenRepo.findValidAccessTokensForUser(id, new Date()));
      return results;
    }
    return Set.of();
  }


  @Override
  public Set<OAuth2RefreshTokenEntity> getAllRefreshTokensForUser(String id) {
    Set<OAuth2RefreshTokenEntity> results = Sets.newLinkedHashSet();
    results.addAll(refreshTokenRepo.findValidRefreshTokensForUser(id, new Date()));
    return results;
  }

  @Override
  public void revokeAccessToken(OAuth2AccessTokenEntity accessToken) {

    try {
      revocationService.revokeToken(accessToken.getJwt(), TokenTypeHint.valueFrom(accessToken.getJwt()));
    } catch (Throwable e) {
      LOG.error(e.getMessage());
    }
  }

  @Override
  public void revokeRefreshToken(OAuth2RefreshTokenEntity refreshToken) {

    try {
      revocationService.revokeToken(refreshToken.getJwt(), TokenTypeHint.valueFrom(refreshToken.getJwt()));
    } catch (Throwable e) {
      LOG.error(e.getMessage());
    }
  }

  @Override
  public OAuth2AccessTokenEntity createAccessToken(OAuth2Authentication authentication) {

    if (isAuthenticationInProgress(authentication.getUserAuthentication())) {
      throw new InvalidGrantException("User is not fully authenticated.");
    }
    OAuth2AccessTokenEntity token =
        super.createAccessToken(scopeFilter.filterScopes(authentication));

    if (isTrackLastUsed) {
      updateClientLastUsed(token);
    }
    if (isAccessTokenOnDatabase) {
      token = saveAccessToken(token);
    }

    eventPublisher.publishEvent(new AccessTokenIssuedEvent(this, token));
    return token;
  }

  @Override
  public OAuth2RefreshTokenEntity createRefreshToken(ClientDetailsEntity client,
      AuthenticationHolderEntity authHolder) {

    OAuth2RefreshTokenEntity token =
        super.createRefreshToken(client, scopeFilter.filterScopes(authHolder));

    eventPublisher.publishEvent(new RefreshTokenIssuedEvent(this, token));
    return token;
  }

  @Override
  public OAuth2AccessTokenEntity refreshAccessToken(String refreshTokenValue,
      TokenRequest authRequest) {

    OAuth2AccessTokenEntity token = super.refreshAccessToken(refreshTokenValue, authRequest);

    if (isTrackLastUsed) {
      updateClientLastUsed(token);
    }
    if (isAccessTokenOnDatabase) {
      token = saveAccessToken(token);
    }

    eventPublisher.publishEvent(new AccessTokenIssuedEvent(this, token));
    return token;
  }

  private boolean isAuthenticationInProgress(Authentication userAuth) {
    return userAuth != null && userAuth.getAuthorities() != null
        && userAuth.getAuthorities().contains(Authorities.ROLE_PRE_AUTHENTICATED);
  }

  private void updateClientLastUsed(OAuth2AccessTokenEntity token) {

    ClientDetailsEntity client = token.getClient();
    ClientLastUsedEntity clientLastUsed = client.getClientLastUsed();
    LocalDate now = LocalDate.now();
    if (clientLastUsed == null) {
      clientLastUsed = new ClientLastUsedEntity(client, now);
      client.setClientLastUsed(clientLastUsed);
    } else {
      if (clientLastUsed.getLastUsed().isBefore(now)) {
        clientLastUsed.setLastUsed(now);
      }
    }
    clientRepo.save(client);
  }

  @Override
  public OAuth2Authentication loadAuthentication(String accessTokenValue)
      throws AuthenticationException {

    OAuth2AccessTokenEntity entity = readAccessToken(accessTokenValue);
    if (isRegistrationAccessToken(entity) || isResourceAccessToken(entity)
        || isAccessTokenOnDatabase) {
      return entity.getAuthenticationHolder().getAuthentication();
    }
    // access token
    Set<String> scopes = entity.getScope();
    Map<String, Object> additionalInfo = entity.getAdditionalInformation();
    Set<String> audiences = new HashSet<>();
    Object audClaimObject = additionalInfo.get(OAuthTokenClaims.AUD_CLAIM);
    if (audClaimObject instanceof List<?> audList) {
      audiences.addAll(audList.stream()
        .filter(String.class::isInstance)
        .map(String.class::cast)
        .collect(Collectors.toSet()));
    }
    String clientId = entity.getClient().getClientId();
    String subject;
    try {
      subject = entity.getJwt().getJWTClaimsSet().getSubject();
    } catch (ParseException e) {
      throw new InvalidTokenException("Subject not found on token");
    }

    if (clientId.equals(valueOf(subject))) {
      return getAuthentication(clientId, scopes, Set.of(new SimpleGrantedAuthority("ROLE_CLIENT")),
          audiences, null);
    }
    IamAccount account = accountRepository.findByUuid(subject)
      .orElseThrow(() -> new InvalidTokenException("User with subject " + subject + " not found"));
    Set<SimpleGrantedAuthority> authorities = account.getAuthorities()
      .stream()
      .map(a -> new SimpleGrantedAuthority(a.getAuthority()))
      .collect(Collectors.toSet());
    scopes = scopeFilter.filterScopes(scopes, account);
    Authentication userAuthentication = buildAuthenticateUser(account.getUsername(), authorities);
    return getAuthentication(clientId, scopes, authorities, audiences, userAuthentication);
  }

  private Authentication buildAuthenticateUser(String username,
      Set<SimpleGrantedAuthority> authorities) {

    SavedUserAuthentication auth = new SavedUserAuthentication();
    auth.setName(username);
    auth.setAuthorities(authorities);
    auth.setAuthenticated(true);
    return auth;
  }

  private boolean isResourceAccessToken(OAuth2AccessTokenEntity entity) {
    return entity.getScope().contains(RESOURCE_TOKEN_SCOPE);
  }

  private boolean isRegistrationAccessToken(OAuth2AccessTokenEntity entity) {
    return entity.getScope().contains(REGISTRATION_TOKEN_SCOPE);
  }

  private boolean isResourceAccessToken(SignedJWT jwt) {
    try {
      return jwt.getJWTClaimsSet()
        .getStringClaim(OAuthTokenClaims.SCOPE_CLAIM)
        .equals(RESOURCE_TOKEN_SCOPE);
    } catch (ParseException e) {
      throw new InvalidTokenException("Token parsing error: " + e.getMessage());
    }
  }

  private boolean isRegistrationAccessToken(SignedJWT jwt) {
    try {
      return jwt.getJWTClaimsSet()
        .getStringClaim(OAuthTokenClaims.SCOPE_CLAIM)
        .equals(REGISTRATION_TOKEN_SCOPE);
    } catch (ParseException e) {
      throw new InvalidTokenException("Token parsing error: " + e.getMessage());
    }
  }

  private OAuth2Authentication getAuthentication(String clientId, Set<String> scopes,
      Set<SimpleGrantedAuthority> authorities, Set<String> audiences,
      Authentication userAuthentication) {

    return new OAuth2Authentication(new OAuth2Request(new HashMap<>(), clientId, authorities, true,
        scopes, audiences, null, null, null), userAuthentication);
  }

  private SignedJWT parseAccessToken(String tokenValue) {
    try {
      return SignedJWT.parse(tokenValue);
    } catch (ParseException e) {
      throw new InvalidTokenException("Token parsing error: " + e.getMessage());
    }
  }

  @Override
  @Transactional
  public OAuth2AccessTokenEntity saveAccessToken(OAuth2AccessTokenEntity accessToken) {

    if (isRegistrationAccessToken(accessToken) || isResourceAccessToken(accessToken)
        || isAccessTokenOnDatabase) {
      return accessTokenRepo.save(accessToken);
    }
    return accessToken;
  }

  @Override
  public OAuth2AccessTokenEntity readAccessToken(String token) {

    SignedJWT jwtToken = parseAccessToken(token);

    if (isRegistrationAccessToken(jwtToken) || isResourceAccessToken(jwtToken)
       || isAccessTokenOnDatabase) {
      return accessTokenRepo.findByTokenValue(sha256(token))
        .orElseThrow(() -> new InvalidTokenException("Access Token not found"));
    }

    OAuth2AccessToken authn = null;

    if (!jwtSigningService.validateSignature(jwtToken)) {
      LOG.warn("Invalid signature for token hash={}", sha256(token));
      throw new InvalidTokenException("Invalid token signature");
    }
    try {
      authn = jwtConverter.convert(jwtToken);
    } catch (ParseException e) {
      LOG.warn("Problem on converting token: {}, token hash={}", e.getMessage(), sha256(token));
      throw new InvalidTokenException("Token parsing error: " + e.getMessage());
    }
    if (authn.getScope().contains(REGISTRATION_TOKEN_SCOPE)
        || authn.getScope().contains(RESOURCE_TOKEN_SCOPE)) {
      return accessTokenRepo.findByTokenValue(sha256(token))
        .orElseThrow(
            () -> new InvalidTokenException("Registration/Resource Access Token not found"));
    }
    // not a Registration/Resource token
    String clientId = extractClientId(authn);
    ClientDetailsEntity client = clientRepo.findByClientId(clientId)
      .orElseThrow(() -> new InvalidTokenException("Client not found with client id " + clientId));
    OAuth2AccessTokenEntity entity = new OAuth2AccessTokenEntity(authn, client);
    entity.setJwt(jwtToken);
    return entity;
  }

  private String extractClientId(OAuth2AccessToken authn) {
    Optional<Object> o =
        Optional.ofNullable(authn.getAdditionalInformation().get(OAuthTokenClaims.CLIENT_ID_CLAIM));
    if (o.isPresent()) {
      return String.valueOf(o.get());
    }
    throw new InvalidTokenException(
        "Access Token " + OAuthTokenClaims.CLIENT_ID_CLAIM + " claim not found");
  }

  @Override
  public OAuth2RefreshTokenEntity getRefreshToken(String refreshTokenValue)
      throws AuthenticationException {
    try {
      return refreshTokenRepo.findByTokenValue(JWTParser.parse(refreshTokenValue))
        .orElseThrow(() -> new InvalidTokenException(
            "Refresh token for value " + refreshTokenValue + " was not found"));
    } catch (ParseException e) {
      throw new InvalidTokenException("Invalid refresh token value");
    }
  }

  public static String sha256(String tokenString) {
    return Hashing.sha256().hashString(tokenString, StandardCharsets.UTF_8).toString();
  }

  public ClientDetailsEntity getClientForToken(JWT jwt, TokenTypeHint tokenType) {

    switch (tokenType) {
      case REFRESH_TOKEN:
        return getClientForRefreshToken((PlainJWT) jwt);
      case ACCESS_TOKEN:
        return getClientForAccessToken((SignedJWT) jwt);
      default:
        return getClientForAccessTokenOnDatabase((SignedJWT) jwt);
    }
  }

  private ClientDetailsEntity getClientForRefreshToken(PlainJWT jwt) {

    OAuth2RefreshTokenEntity rt = refreshTokenRepo.findByTokenValue(jwt)
      .orElseThrow(() -> new InvalidTokenException("Invalid refresh token value"));
    return rt.getClient();
  }

  public ClientDetailsEntity getClientForAccessToken(SignedJWT jwt) {

    if (isAccessTokenOnDatabase) {
      return getClientForAccessTokenOnDatabase(jwt);
    }
    String clientId = null;
    try {
      clientId = jwt.getJWTClaimsSet().getStringClaim(OAuthTokenClaims.CLIENT_ID_CLAIM);
    } catch (Throwable e) {
      throw new InvalidTokenException("Invalid access token value: " + e.getMessage());
    }
    if (clientId == null) {
      throw new InvalidTokenException("Invalid access token value: null client id claim");
    }
    return clientRepo.findByClientId(clientId)
      .orElseThrow(() -> new InvalidTokenException("Invalid access token value: client id not found"));
  }

  private ClientDetailsEntity getClientForAccessTokenOnDatabase(SignedJWT jwt) {

    OAuth2AccessTokenEntity at = accessTokenRepo.findByTokenValue(sha256(jwt.serialize()))
      .orElseThrow(() -> new InvalidTokenException("Invalid access token value"));
    return at.getClient();
  }

}
