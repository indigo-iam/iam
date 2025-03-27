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
import java.util.Optional;
import java.util.Set;

import javax.transaction.Transactional;

import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mitre.oauth2.model.AuthenticationHolderEntity;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.ClientLastUsedEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.mitre.oauth2.service.SystemScopeService;
import org.mitre.oauth2.service.impl.DefaultOAuth2ProviderTokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.stereotype.Service;

import com.google.common.collect.Sets;
import com.google.common.hash.Hashing;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.audit.events.tokens.AccessTokenIssuedEvent;
import it.infn.mw.iam.audit.events.tokens.RefreshTokenIssuedEvent;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.scope.pdp.ScopeFilter;
import it.infn.mw.iam.core.oauth.tokens.JwtToOAuth2AccessTokenConverter;
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

  private static final String CLIENT_ID_CLAIM = "client_id";

  private final IamOAuthAccessTokenRepository accessTokenRepo;
  private final IamOAuthRefreshTokenRepository refreshTokenRepo;
  private final IamClientRepository clientRepo;
  private final IamAccountRepository accountRepository;
  private final ApplicationEventPublisher eventPublisher;
  private final IamProperties iamProperties;
  private final ScopeFilter scopeFilter;
  private final JwtToOAuth2AccessTokenConverter jwtConverter;
  private final JWTSigningAndValidationService jwtSigningService;

  public IamTokenService(IamOAuthAccessTokenRepository accessTokenRepo,
      IamOAuthRefreshTokenRepository refreshTokenRepo, IamClientRepository clientRepo,
      IamAccountRepository accountRepository, ApplicationEventPublisher eventPublisher,
      IamProperties iamProperties, ScopeFilter scopeFilter,
      JwtToOAuth2AccessTokenConverter jwtConverter,
      JWTSigningAndValidationService jwtSigningService) {

    this.accessTokenRepo = accessTokenRepo;
    this.refreshTokenRepo = refreshTokenRepo;
    this.clientRepo = clientRepo;
    this.accountRepository = accountRepository;
    this.eventPublisher = eventPublisher;
    this.iamProperties = iamProperties;
    this.scopeFilter = scopeFilter;
    this.jwtConverter = jwtConverter;
    this.jwtSigningService = jwtSigningService;
  }

  @Override
  public Set<OAuth2AccessTokenEntity> getAllAccessTokensForUser(String id) {

    Set<OAuth2AccessTokenEntity> results = Sets.newLinkedHashSet();
    results.addAll(accessTokenRepo.findValidAccessTokensForUser(id, new Date()));
    return results;
  }


  @Override
  public Set<OAuth2RefreshTokenEntity> getAllRefreshTokensForUser(String id) {
    Set<OAuth2RefreshTokenEntity> results = Sets.newLinkedHashSet();
    results.addAll(refreshTokenRepo.findValidRefreshTokensForUser(id, new Date()));
    return results;
  }

  @Override
  public void revokeAccessToken(OAuth2AccessTokenEntity accessToken) {
    accessTokenRepo.delete(accessToken);
  }

  @Override
  public void revokeRefreshToken(OAuth2RefreshTokenEntity refreshToken) {
    refreshTokenRepo.delete(refreshToken);
  }

  @Override
  public OAuth2AccessTokenEntity createAccessToken(OAuth2Authentication authentication) {

    OAuth2AccessTokenEntity token =
        super.createAccessToken(scopeFilter.filterScopes(authentication));

    if (iamProperties.getClient().isTrackLastUsed()) {
      updateClientLastUsed(token);
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

    if (iamProperties.getClient().isTrackLastUsed()) {
      updateClientLastUsed(token);
    }

    eventPublisher.publishEvent(new AccessTokenIssuedEvent(this, token));
    return token;
  }

  private void updateClientLastUsed(OAuth2AccessTokenEntity token) {
    ClientDetailsEntity client = token.getClient();
    ClientLastUsedEntity clientLastUsed = client.getClientLastUsed();
    LocalDate now = LocalDate.now();

    if (clientLastUsed == null) {
      clientLastUsed = new ClientLastUsedEntity(client, now);
      client.setClientLastUsed(clientLastUsed);
    } else {
      LocalDate lastUsed = clientLastUsed.getLastUsed();
      if (lastUsed.isBefore(now)) {
        clientLastUsed.setLastUsed(now);
      }
    }
  }

  @Override
  public OAuth2Authentication loadAuthentication(String accessTokenValue)
      throws AuthenticationException {

    OAuth2AccessTokenEntity entity = readAccessToken(accessTokenValue);
    if (isRegistrationAccessToken(entity) || isResourceAccessToken(entity)) {
      return entity.getAuthenticationHolder().getAuthentication();
    }
    // access token
    Set<String> scopes = entity.getScope();
    Set<String> audiences = new HashSet<>();
    Object audClaimObject = entity.getAdditionalInformation().get("aud");
    if (audClaimObject instanceof List<?>) {
      audiences.addAll(((List<?>) audClaimObject).stream()
        .filter(String.class::isInstance)
        .map(String.class::cast)
        .toList());
    }
    if (entity.getAdditionalInformation().get(CLIENT_ID_CLAIM) == null) {
      throw new InvalidTokenException("client id not found on token");
    }
    String clientId = String.valueOf(entity.getAdditionalInformation().get(CLIENT_ID_CLAIM));
    if (entity.getAdditionalInformation().get("sub") == null) {
      throw new InvalidTokenException("sub not found on token");
    }
    String subject = String.valueOf(entity.getAdditionalInformation().get("sub"));
    if (clientId.equals(valueOf(subject))) {
      return getAuthentication(clientId, scopes, Set.of(new SimpleGrantedAuthority("ROLE_CLIENT")),
          audiences, null);
    }
    IamAccount account = accountRepository.findByUuid(subject)
      .orElseThrow(() -> new InvalidTokenException("User with subject " + subject + " not found"));
    Set<SimpleGrantedAuthority> authorities = new HashSet<>();
    account.getAuthorities()
      .forEach(a -> authorities.add(new SimpleGrantedAuthority(a.getAuthority())));
    scopes = scopeFilter.filterScopes(scopes, account);
    UsernamePasswordAuthenticationToken userAuthentication =
        new UsernamePasswordAuthenticationToken(account.getUsername(), null, authorities);
    return getAuthentication(clientId, scopes, authorities, audiences, userAuthentication);
  }

  private boolean isResourceAccessToken(OAuth2AccessTokenEntity entity) {
    return entity.getScope().contains(RESOURCE_TOKEN_SCOPE);
  }

  private boolean isRegistrationAccessToken(OAuth2AccessTokenEntity entity) {
    return entity.getScope().contains(REGISTRATION_TOKEN_SCOPE);
  }

  private OAuth2Authentication getAuthentication(String clientId, Set<String> scopes,
      Set<SimpleGrantedAuthority> authorities, Set<String> audiences,
      UsernamePasswordAuthenticationToken userAuthentication) {

    return new OAuth2Authentication(new OAuth2Request(new HashMap<>(), clientId, authorities, true,
        scopes, audiences, null, null, null), userAuthentication);
  }

  @Override
  @Transactional
  public OAuth2AccessTokenEntity saveAccessToken(OAuth2AccessTokenEntity accessToken) {

    if (accessToken.getScope().contains(SystemScopeService.REGISTRATION_TOKEN_SCOPE)
        || accessToken.getScope().contains(SystemScopeService.RESOURCE_TOKEN_SCOPE)) {
      return accessTokenRepo.save(accessToken);
    }
    return accessToken;
  }

  @Override
  public OAuth2AccessTokenEntity readAccessToken(String accessTokenValue) {

    OAuth2AccessToken authn = null;
    SignedJWT jwtToken = null;
    try {
      jwtToken = SignedJWT.parse(accessTokenValue);
    } catch (ParseException e) {
      throw new InvalidTokenException("Token parsing error: " + e.getMessage());
    }
    if (!jwtSigningService.validateSignature(jwtToken)) {
      throw new InvalidTokenException("Invalid token signature");
    }
    try {
      authn = jwtConverter.convert(jwtToken);
    } catch (ParseException e) {
      throw new InvalidTokenException("Token parsing error: " + e.getMessage());
    }
    if (authn.getScope().contains(REGISTRATION_TOKEN_SCOPE)
        || authn.getScope().contains(RESOURCE_TOKEN_SCOPE)) {
      return accessTokenRepo.findByTokenValue(sha256(accessTokenValue))
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
    Optional<Object> o = Optional.ofNullable(authn.getAdditionalInformation().get(CLIENT_ID_CLAIM));
    if (o.isPresent()) {
      return String.valueOf(o.get());
    }
    throw new InvalidTokenException("Access Token " + CLIENT_ID_CLAIM + " claim not found");
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

}
