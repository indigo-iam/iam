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
import static org.mitre.openid.connect.request.ConnectRequestParameters.CODE_CHALLENGE;
import static org.mitre.openid.connect.request.ConnectRequestParameters.CODE_CHALLENGE_METHOD;
import static org.mitre.openid.connect.request.ConnectRequestParameters.CODE_VERIFIER;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mitre.oauth2.model.AuthenticationHolderEntity;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.mitre.oauth2.model.PKCEAlgorithm;
import org.mitre.oauth2.model.SavedUserAuthentication;
import org.mitre.oauth2.model.SystemScope;
import org.mitre.oauth2.service.OAuth2TokenEntityService;
import org.mitre.oauth2.service.SystemScopeService;
import org.mitre.openid.connect.service.OIDCTokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.google.common.base.Strings;
import com.google.common.collect.Sets;
import com.google.common.hash.Hashing;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.audit.events.tokens.AccessTokenIssuedEvent;
import it.infn.mw.iam.audit.events.tokens.RefreshTokenIssuedEvent;
import it.infn.mw.iam.authn.util.Authorities;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.profile.JWTProfile;
import it.infn.mw.iam.core.oauth.profile.JWTProfileResolver;
import it.infn.mw.iam.core.oauth.profile.iam.IamExtraClaimNames;
import it.infn.mw.iam.core.oauth.revocation.TokenRevocationService;
import it.infn.mw.iam.core.oauth.scope.pdp.ScopeFilter;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAuthenticationHolderRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;

@SuppressWarnings("deprecation")
// @Service("defaultOAuth2ProviderTokenService")
@Service
@Primary
public class IamTokenService implements OAuth2TokenEntityService {

  public static final Logger LOG = LoggerFactory.getLogger(IamTokenService.class);

  public static final String EXPIRES_IN_KEY = "expires_in";
  public static final String INVALID_PARAMETER = "Value of 'expires_in' parameter is not valid";


  private final IamOAuthAccessTokenRepository accessTokenRepo;
  private final IamOAuthRefreshTokenRepository refreshTokenRepo;
  private final IamAuthenticationHolderRepository authenticationHolderRepo;
  private final ClientService clientService;
  private final IamClientRepository clientRepo;
  private final IamAccountRepository accountRepository;
  private final JWTSigningAndValidationService jwtSigningService;
  private final TokenRevocationService revocationService;
  private final OIDCTokenService connectTokenService;
  private final SystemScopeService scopeService;
  private final JWTProfileResolver profileResolver;
  private final ApplicationEventPublisher eventPublisher;
  private final IamProperties iamProperties;
  private final ScopeFilter scopeFilter;
  private final Clock clock;

  public IamTokenService(Clock clock, IamOAuthAccessTokenRepository accessTokenRepo,
      IamOAuthRefreshTokenRepository refreshTokenRepo,
      IamAuthenticationHolderRepository authenticationHolderRepo, IamClientRepository clientRepo,
      ClientService clientService, IamAccountRepository accountRepository,
      JWTSigningAndValidationService jwtSigningService, TokenRevocationService revocationService,
      OIDCTokenService connectTokenService, SystemScopeService scopeService,
      JWTProfileResolver profileResolver, ApplicationEventPublisher eventPublisher,
      IamProperties iamProperties, ScopeFilter scopeFilter) {

    this.accessTokenRepo = accessTokenRepo;
    this.refreshTokenRepo = refreshTokenRepo;
    this.authenticationHolderRepo = authenticationHolderRepo;
    this.clientService = clientService;
    this.clientRepo = clientRepo;
    this.accountRepository = accountRepository;
    this.jwtSigningService = jwtSigningService;
    this.revocationService = revocationService;
    this.connectTokenService = connectTokenService;
    this.scopeService = scopeService;
    this.profileResolver = profileResolver;
    this.eventPublisher = eventPublisher;
    this.iamProperties = iamProperties;
    this.scopeFilter = scopeFilter;
    this.clock = clock;
  }

  @Override
  public Set<OAuth2AccessTokenEntity> getAllAccessTokensForUser(String id) {

    Set<OAuth2AccessTokenEntity> results = Sets.newLinkedHashSet();
    if (iamProperties.getAccessToken().isStoreOnDatabase()) {
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
  public OAuth2AccessTokenEntity saveAccessToken(OAuth2AccessTokenEntity accessToken) {

    if (iamProperties.getAccessToken().isStoreOnDatabase() || isRegistrationAccessToken(accessToken)
        || isResourceAccessToken(accessToken)) {

      AuthenticationHolderEntity ah =
          authenticationHolderRepo.save(accessToken.getAuthenticationHolder());
      accessToken.setAuthenticationHolder(ah);
      return accessTokenRepo.saveAndFlush(accessToken);
    }
    return accessToken;
  }

  @Override
  @Transactional(value = "defaultTransactionManager")
  public OAuth2AccessTokenEntity createAccessToken(OAuth2Authentication authentication) {

    if (authentication == null || authentication.getOAuth2Request() == null) {
      throw new AuthenticationCredentialsNotFoundException("No authentication credentials found");
    }

    if (isAuthenticationInProgress(authentication.getUserAuthentication())) {
      throw new InvalidGrantException("User is not fully authenticated.");
    }

    OAuth2Request request = authentication.getOAuth2Request();

    ClientDetailsEntity client = clientService.findClientByClientId(request.getClientId())
      .orElseThrow(() -> new InvalidClientException("Client not found: " + request.getClientId()));

    if (!client.isActive()) {
      throw new InvalidClientException("Client is suspended: " + request.getClientId());
    }

    Optional<IamAccount> account = Optional.empty();
    if (!authentication.isClientOnly()) {
      String username = authentication.getName();
      account = accountRepository.findByUsername(username);
    }

    // handle the PKCE code challenge if present
    if (request.getExtensions().containsKey(CODE_CHALLENGE)) {
      String challenge = (String) request.getExtensions().get(CODE_CHALLENGE);
      PKCEAlgorithm alg =
          PKCEAlgorithm.parse((String) request.getExtensions().get(CODE_CHALLENGE_METHOD));

      String verifier = request.getRequestParameters().get(CODE_VERIFIER);

      if (alg.equals(PKCEAlgorithm.plain)) {
        // do a direct string comparison
        if (!challenge.equals(verifier)) {
          throw new InvalidRequestException("Code challenge and verifier do not match");
        }
      } else if (alg.equals(PKCEAlgorithm.S256)) {
        // hash the verifier
        try {
          MessageDigest digest = MessageDigest.getInstance("SHA-256");
          String hash =
              Base64URL.encode(digest.digest(verifier.getBytes(StandardCharsets.US_ASCII)))
                .toString();
          if (!challenge.equals(hash)) {
            throw new InvalidRequestException("Code challenge and verifier do not match");
          }
        } catch (NoSuchAlgorithmException e) {
          LOG.error("Unknown algorithm for PKCE digest", e);
        }
      }

    }

    Instant tokenIssueInstant = clock.instant();
    OAuth2AccessTokenEntity accessToken = new OAuth2AccessTokenEntity();
    accessToken.setClient(client);
    // scopes
    Set<SystemScope> scopes =
        scopeService.fromStrings(scopeFilter.filterScopes(request.getScope(), authentication));
    scopes = scopeService.removeReservedScopes(scopes);
    accessToken.setScope(scopeService.toStrings(scopes));
    accessToken
      .setExpiration(computeExpiration(request.getRequestParameters(), client, tokenIssueInstant));

    AuthenticationHolderEntity authHolder = new AuthenticationHolderEntity();
    authHolder.setAuthentication(authentication);
    accessToken.setAuthenticationHolder(authHolder);

    // attach a refresh token, if this client is allowed to request them, the user gets the
    // offline scope and grant type differs from client credentials
    if (client.isAllowRefresh()
        && accessToken.getScope().contains(SystemScopeService.OFFLINE_ACCESS)
        && !request.getGrantType().equals("client_credentials")) {

      accessToken.setRefreshToken(createRefreshToken(client, authHolder));
    }

    JWTProfile profile = profileResolver.resolveProfile(client.getScope());

    JWTClaimsSet atClaims = profile.getAccessTokenBuilder()
      .buildAccessToken(accessToken, authentication, account, tokenIssueInstant);

    accessToken.setJwt(signClaims(atClaims));
    accessToken.hashMe();

    /**
     * Authorization request scope MUST include "openid" in OIDC, but access token request may or
     * may not include the scope parameter. As long as the AuthorizationRequest has the proper
     * scope, we can consider this a valid OpenID Connect request. Otherwise, we consider it to be a
     * vanilla OAuth2 request.
     * 
     * Also, there must be a user authentication involved in the request for it to be considered
     * OIDC and not OAuth, so we check for that as well.
     */
    if (request.getScope().contains(SystemScopeService.OPENID_SCOPE) && account.isPresent()) {

      JWT idToken = connectTokenService.createIdToken(client, request, Date.from(tokenIssueInstant),
          account.get().getUuid(), accessToken);

      accessToken.setIdToken(idToken);
    }

    if (iamProperties.getClient().isTrackLastUsed()) {
      clientService.useClient(client);
    }
    OAuth2AccessTokenEntity savedAccessToken = saveAccessToken(accessToken);

    eventPublisher.publishEvent(new AccessTokenIssuedEvent(this, savedAccessToken));
    return savedAccessToken;
  }

  @Override
  public OAuth2RefreshTokenEntity createRefreshToken(ClientDetailsEntity client,
      AuthenticationHolderEntity authHolder) {

    String jti = UUID.randomUUID().toString();
    Date iat = new Date();
    Date exp = null;

    if (client.getRefreshTokenValiditySeconds() != null
        && client.getRefreshTokenValiditySeconds() > 0) {
      exp = new Date(System.currentTimeMillis() + client.getRefreshTokenValiditySeconds() * 1000L);
    }

    JWTClaimsSet.Builder refreshClaims = new JWTClaimsSet.Builder();
    refreshClaims.jwtID(jti);
    refreshClaims.issuer(iamProperties.getIssuer());
    refreshClaims.issueTime(iat);
    refreshClaims.expirationTime(exp);
    refreshClaims.serializeNullClaims(false);
    PlainJWT refreshJwt = new PlainJWT(refreshClaims.build());

    OAuth2RefreshTokenEntity refreshToken = new OAuth2RefreshTokenEntity();
    refreshToken.setExpiration(exp);
    refreshToken.setJwt(refreshJwt);
    refreshToken.setAuthenticationHolder(scopeFilter.filterScopes(authHolder));
    refreshToken.setClient(client);

    refreshToken = saveRefreshToken(refreshToken);
    eventPublisher.publishEvent(new RefreshTokenIssuedEvent(this, refreshToken));

    return refreshToken;
  }

  @Override
  public OAuth2AccessTokenEntity refreshAccessToken(String refreshTokenValue,
      TokenRequest authRequest) {

    if (Strings.isNullOrEmpty(refreshTokenValue)) {
      throw new InvalidTokenException("Invalid refresh token: null or empty value");
    }
    OAuth2RefreshTokenEntity refreshToken = getRefreshToken(refreshTokenValue);
    ClientDetailsEntity client = refreshToken.getClient();
    AuthenticationHolderEntity authHolder = refreshToken.getAuthenticationHolder();

    OAuth2Request newOAuth2Request =
        authHolder.getAuthentication().getOAuth2Request().refresh(authRequest);
    OAuth2Authentication newOAuth2Authentication =
        new OAuth2Authentication(newOAuth2Request, authHolder.getUserAuth());

    JWTProfile profile = profileResolver.resolveProfile(client.getScope());

    Optional<IamAccount> account = Optional.empty();
    if (!newOAuth2Authentication.isClientOnly()) {
      String username = newOAuth2Authentication.getName();
      account = accountRepository.findByUsername(username);
    }

    ClientDetailsEntity requestingClient =
        clientService.findClientByClientId(authRequest.getClientId())
          .orElseThrow(
              () -> new IllegalStateException("Invalid requesting client id: client not found"));

    /* client validation */
    if (!requestingClient.isActive()) {
      throw new InvalidClientException("Suspended client '" + client.getClientId() + "'");
    }
    if (!requestingClient.isAllowRefresh()) {
      throw new InvalidClientException(
          "Client '" + client.getClientId() + "' does not allow refreshing access token!");
    }
    if (!requestingClient.getClientId().equals(client.getClientId())) {
      revocationService.revokeRefreshToken(refreshToken);
      throw new InvalidClientException("Client does not own the presented refresh token");
    }

    /* refresh token validation */
    if (refreshToken.isExpired()) {
      revocationService.revokeRefreshToken(refreshToken);
      throw new InvalidTokenException("Expired refresh token: " + refreshTokenValue);
    }

    Instant tokenIssueInstant = clock.instant();
    OAuth2AccessTokenEntity token = new OAuth2AccessTokenEntity();

    token.setScope(computeScopes(authRequest, refreshToken, account));

    token.setClient(client);
    token.setExpiration(
        computeExpiration(authRequest.getRequestParameters(), client, tokenIssueInstant));

    if (client.isReuseRefreshToken()) {
      // if the client re-uses refresh tokens, do that
      token.setRefreshToken(refreshToken);
    } else {
      // otherwise, make a new refresh token
      token.setRefreshToken(createRefreshToken(client, authHolder));
      // clean up the old refresh token
      revocationService.revokeRefreshToken(refreshToken);
    }

    token.setAuthenticationHolder(authHolder);


    JWTClaimsSet atClaims = profile.getAccessTokenBuilder()
      .buildAccessToken(token, newOAuth2Authentication, account, tokenIssueInstant);

    token.setJwt(signClaims(atClaims));
    token.hashMe();

    /**
     * Authorization request scope MUST include "openid" in OIDC, but access token request may or
     * may not include the scope parameter. As long as the AuthorizationRequest has the proper
     * scope, we can consider this a valid OpenID Connect request. Otherwise, we consider it to be a
     * vanilla OAuth2 request.
     * 
     * Also, there must be a user authentication involved in the request for it to be considered
     * OIDC and not OAuth, so we check for that as well.
     */
    if (newOAuth2Request.getScope().contains(SystemScopeService.OPENID_SCOPE)
        && account.isPresent()) {

      JWT idToken = connectTokenService.createIdToken(client, newOAuth2Request,
          Date.from(tokenIssueInstant), account.get().getUuid(), token);

      token.setIdToken(idToken);
    }

    if (iamProperties.getClient().isTrackLastUsed()) {
      clientService.useClient(token.getClient());
    }
    if (iamProperties.getAccessToken().isStoreOnDatabase()) {
      token = saveAccessToken(token);
    }

    eventPublisher.publishEvent(new AccessTokenIssuedEvent(this, token));
    return token;
  }

  private Set<String> computeScopes(TokenRequest authRequest, OAuth2RefreshTokenEntity refreshToken,
      Optional<IamAccount> account) {

    /* load reserved scopes from db */
    Set<String> reservedScopes = scopeService.toStrings(scopeService.getReserved());
    /* retrieve authorized scopes from refresh token */
    Set<String> authorizedScopes = Sets.newHashSet(
        refreshToken.getAuthenticationHolder().getAuthentication().getOAuth2Request().getScope());
    authorizedScopes.removeAll(reservedScopes);
    /* get cuirrent requested scopes, if present */
    Set<String> requestedScopes = new HashSet<>();
    if (authRequest.getScope() != null) {
      requestedScopes.addAll(authRequest.getScope());
    }
    requestedScopes.removeAll(reservedScopes);

    /* compute scopes to be filtered */
    Set<String> scopesToFilter = new HashSet<>();
    if (requestedScopes.isEmpty()) {
      scopesToFilter.addAll(authorizedScopes);
    } else {
      /* Check for up-scoping */
      if (!scopeService.scopesMatch(authorizedScopes, requestedScopes)) {
        String errorMsg = "Up-scoping is not allowed.";
        LOG.error(errorMsg);
        throw new InvalidScopeException(errorMsg);
      }
      scopesToFilter.addAll(requestedScopes);
    }

    if (account.isPresent()) {
      return scopeFilter.filterScopes(scopesToFilter, account.get());
    }
    return scopeFilter.filterScopes(refreshToken.getAuthenticationHolder()).getScope();
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
        || iamProperties.getAccessToken().isStoreOnDatabase()) {
      return entity.getAuthenticationHolder().getAuthentication();
    }
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
        || iamProperties.getAccessToken().isStoreOnDatabase()) {
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
      String scopeClaim = jwt.getJWTClaimsSet().getStringClaim(IamExtraClaimNames.SCOPE);
      return Objects.nonNull(scopeClaim) && RESOURCE_TOKEN_SCOPE.equals(scopeClaim);
    } catch (ParseException e) {
      throw new InvalidTokenException("Token parsing error: " + e.getMessage());
    }
  }

  private boolean isRegistrationAccessToken(SignedJWT jwt) {
    try {
      String scopeClaim = jwt.getJWTClaimsSet().getStringClaim(IamExtraClaimNames.SCOPE);
      return Objects.nonNull(scopeClaim) && REGISTRATION_TOKEN_SCOPE.equals(scopeClaim);
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

  private Date computeExpiration(Map<String, String> requestParameters, ClientDetailsEntity client,
      Instant tokenIssueInstant) {

    Optional<Integer> expiresIn = getExpiresIn(requestParameters);
    int validityInSeconds = 3600;
    if (client.getAccessTokenValiditySeconds() != null
        && client.getAccessTokenValiditySeconds() > 0) {
      validityInSeconds = client.getAccessTokenValiditySeconds().intValue();
    }
    if (expiresIn.isEmpty() || expiresIn.get() <= 0) {
      return Date.from(tokenIssueInstant.plus(validityInSeconds, ChronoUnit.SECONDS));
    }
    return Date.from(
        tokenIssueInstant.plus(Math.min(expiresIn.get(), validityInSeconds), ChronoUnit.SECONDS));
  }

  private Optional<Integer> getExpiresIn(Map<String, String> requestParameters) {

    try {
      if (requestParameters.containsKey(EXPIRES_IN_KEY)) {
        return Optional.of(Integer.valueOf(requestParameters.get(EXPIRES_IN_KEY)));
      }
      return Optional.empty();
    } catch (NumberFormatException e) {
      throw new InvalidRequestException(INVALID_PARAMETER);
    }
  }

  private SignedJWT signClaims(JWTClaimsSet claims) {
    JWSAlgorithm signingAlg = jwtSigningService.getDefaultSigningAlgorithm();

    JWSHeader header = new JWSHeader(signingAlg, null, null, null, null, null, null, null, null,
        null, jwtSigningService.getDefaultSignerKeyId(), null, null);
    SignedJWT signedJWT = new SignedJWT(header, claims);

    jwtSigningService.signJwt(signedJWT);
    return signedJWT;

  }

  public static String sha256(String tokenString) {
    return Hashing.sha256().hashString(tokenString, StandardCharsets.UTF_8).toString();
  }

  @Override
  public OAuth2AccessTokenEntity getAccessToken(OAuth2Authentication authentication) {
    throw new UnsupportedOperationException(
        "Unable to look up access token from authentication object.");
  }

  @Override
  public OAuth2RefreshTokenEntity getRefreshToken(String refreshTokenValue) {

    PlainJWT jwt;
    try {
      jwt = PlainJWT.parse(refreshTokenValue);
    } catch (ParseException e) {
      throw new InvalidTokenException("Invalid refresh token: " + e.getMessage());
    }
    return refreshTokenRepo.findByTokenValue(jwt)
      .orElseThrow(() -> new InvalidTokenException("Invalid refresh token: token not found"));
  }

  @Override
  public List<OAuth2AccessTokenEntity> getAccessTokensForClient(ClientDetailsEntity client) {

    if (iamProperties.getAccessToken().isStoreOnDatabase()) {
      return accessTokenRepo.findAccessTokens(client.getId());
    }
    return List.of();
  }

  @Override
  public List<OAuth2RefreshTokenEntity> getRefreshTokensForClient(ClientDetailsEntity client) {

    return refreshTokenRepo.findByClientId(client.getId());
  }

  @Override
  public void clearExpiredTokens() {

    // GarbageCollector will remove them
    return;
  }

  @Override
  public OAuth2RefreshTokenEntity saveRefreshToken(OAuth2RefreshTokenEntity refreshToken) {

    refreshToken.setAuthenticationHolder(
        authenticationHolderRepo.save(refreshToken.getAuthenticationHolder()));
    return refreshTokenRepo.save(refreshToken);
  }

  @Override
  public OAuth2AccessTokenEntity getAccessTokenById(Long id) {

    return accessTokenRepo.findById(id).orElse(null);
  }

  @Override
  public OAuth2RefreshTokenEntity getRefreshTokenById(Long id) {

    return refreshTokenRepo.findById(id).orElse(null);
  }

  @Override
  public OAuth2AccessTokenEntity getRegistrationAccessTokenForClient(ClientDetailsEntity client) {

    return accessTokenRepo.findRegistrationToken(client.getId()).orElse(null);
  }
}
