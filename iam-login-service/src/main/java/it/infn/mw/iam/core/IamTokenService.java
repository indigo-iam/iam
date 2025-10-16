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
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mitre.oauth2.model.AuthenticationHolderEntity;
import org.mitre.oauth2.model.ClientDetailsEntity;
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
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.stereotype.Service;

import com.google.common.collect.Sets;
import com.google.common.hash.Hashing;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.audit.events.tokens.AccessTokenIssuedEvent;
import it.infn.mw.iam.audit.events.tokens.RefreshTokenIssuedEvent;
import it.infn.mw.iam.authn.util.Authorities;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.profile.iam.IamExtraClaimNames;
import it.infn.mw.iam.core.oauth.revocation.TokenRevocationService;
import it.infn.mw.iam.core.oauth.scope.pdp.ScopeFilter;
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
  private final ClientService clientService;
  private final IamClientRepository clientRepo;
  private final IamAccountRepository accountRepository;
  private final JWTSigningAndValidationService jwtSigningService;
  private final TokenRevocationService revocationService;
  private final ApplicationEventPublisher eventPublisher;
  private final ScopeFilter scopeFilter;
  private boolean isTrackLastUsed;
  private boolean isAccessTokenOnDatabase;

  public IamTokenService(IamOAuthAccessTokenRepository accessTokenRepo,
      IamOAuthRefreshTokenRepository refreshTokenRepo, IamClientRepository clientRepo, ClientService clientService,
      IamAccountRepository accountRepository, JWTSigningAndValidationService jwtSigningService,
      TokenRevocationService revocationService, ApplicationEventPublisher eventPublisher,
      IamProperties iamProperties, ScopeFilter scopeFilter) {

    this.accessTokenRepo = accessTokenRepo;
    this.refreshTokenRepo = refreshTokenRepo;
    this.clientService = clientService;
    this.clientRepo = clientRepo;
    this.accountRepository = accountRepository;
    this.jwtSigningService = jwtSigningService;
    this.revocationService = revocationService;
    this.eventPublisher = eventPublisher;
    this.scopeFilter = scopeFilter;
    this.isTrackLastUsed = iamProperties.getClient().isTrackLastUsed();
    this.isAccessTokenOnDatabase = iamProperties.getAccessToken().isStoreOnDatabase();
  }

  @Override
  public Set<OAuth2AccessTokenEntity> getAllAccessTokensForUser(String id) {

    Set<OAuth2AccessTokenEntity> results = Sets.newLinkedHashSet();
    if (isAccessTokenOnDatabase) {
      results.addAll(accessTokenRepo.findAccessTokensForUser(id));
    }
    return results;
  }


  @Override
  public Set<OAuth2RefreshTokenEntity> getAllRefreshTokensForUser(String id) {

    Set<OAuth2RefreshTokenEntity> results = Sets.newLinkedHashSet();
    results.addAll(refreshTokenRepo.findRefreshTokensForUser(id));
    return results;
  }

  @Override
  public void revokeAccessToken(OAuth2AccessTokenEntity accessToken) {

    try {
      revocationService.revokeAccessToken(accessToken);
    } catch (Throwable e) {
      LOG.error(e.getMessage());
    }
  }

  @Override
  public void revokeRefreshToken(OAuth2RefreshTokenEntity refreshToken) {

    try {
      revocationService.revokeRefreshToken(refreshToken);
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
      clientService.useClient(token.getClient());
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
      clientService.useClient(token.getClient());
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
    Object audClaimObject = additionalInfo.get(JWTClaimNames.AUDIENCE);
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

    if (clientId.equals(subject)) {
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

  @Override
  public OAuth2AccessTokenEntity readAccessToken(String token) {

    SignedJWT jwtToken = parseAccessToken(token);

    if (isRegistrationAccessToken(jwtToken) || isResourceAccessToken(jwtToken)
        || isAccessTokenOnDatabase) {
      return accessTokenRepo.findByTokenValue(sha256(token))
        .orElseThrow(() -> new InvalidTokenException("Access Token not found"));
    }

    /* It's an access-token not saved on database */
    verifySignature(jwtToken);
    return buildAccessToken(jwtToken);
  }

  private OAuth2AccessTokenEntity buildAccessToken(SignedJWT jwtToken) {

    OAuth2AccessTokenEntity entity = new OAuth2AccessTokenEntity();

    JWTClaimsSet claims;
    try {
      claims = jwtToken.getJWTClaimsSet();
    } catch (ParseException e) {
      throw new InvalidTokenException(e.getMessage());
    }
    entity.setJwt(jwtToken);
    entity.setExpiration(claims.getExpirationTime());
    entity.setScope(claims.getClaims().containsKey(IamExtraClaimNames.SCOPE)
        ? Set.of(claims.getClaim(IamExtraClaimNames.SCOPE).toString().split(" "))
        : Set.of());
    entity.setTokenType(OAuth2AccessToken.BEARER_TYPE);
    if (claims.getClaims().containsKey("refresh_token")) {
      String refreshTokenValue = valueOf(claims.getClaim("refresh_token"));
      OAuth2RefreshToken refreshToken = new DefaultOAuth2RefreshToken(refreshTokenValue);
      entity.setRefreshToken(refreshToken);
    }
    entity.setTokenValueHash(sha256(jwtToken.serialize()));
    entity.setClient(extractClient(jwtToken));
    entity.getAdditionalInformation().clear();
    entity.getAdditionalInformation().putAll(claims.getClaims());
    entity.getAdditionalInformation().remove(JWTClaimNames.EXPIRATION_TIME);
    entity.getAdditionalInformation().remove(IamExtraClaimNames.SCOPE);
    return entity;
  }

  private ClientDetailsEntity extractClient(SignedJWT jwtToken) {

    Optional<Object> claimClientId;
    try {
      claimClientId =
          Optional.ofNullable(jwtToken.getJWTClaimsSet().getClaim(IamExtraClaimNames.CLIENT_ID));
    } catch (ParseException e) {
      throw new InvalidTokenException(e.getMessage());
    }
    if (claimClientId.isEmpty()) {
      throw new InvalidTokenException(IamExtraClaimNames.CLIENT_ID + " not found on token");
    }
    String clientId = String.valueOf(claimClientId.get());
    return clientRepo.findByClientId(clientId)
      .orElseThrow(() -> new InvalidTokenException("Client not found with client id " + clientId));
  }

  private void verifySignature(SignedJWT jwtToken) {

    if (!jwtSigningService.validateSignature(jwtToken)) {
      LOG.warn("Invalid signature for token {}", jwtToken.getPayload().toJSONObject().toString());
      throw new InvalidTokenException("Invalid token signature");
    }
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
        .getStringClaim(IamExtraClaimNames.SCOPE)
        .equals(RESOURCE_TOKEN_SCOPE);
    } catch (ParseException e) {
      throw new InvalidTokenException("Token parsing error: " + e.getMessage());
    }
  }

  private boolean isRegistrationAccessToken(SignedJWT jwt) {
    try {
      return jwt.getJWTClaimsSet()
        .getStringClaim(IamExtraClaimNames.SCOPE)
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

  public static String sha256(String tokenString) {
    return Hashing.sha256().hashString(tokenString, StandardCharsets.UTF_8).toString();
  }
}
