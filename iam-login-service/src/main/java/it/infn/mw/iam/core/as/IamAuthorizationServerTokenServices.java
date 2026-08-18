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
package it.infn.mw.iam.core.as;

import static java.nio.charset.StandardCharsets.US_ASCII;

import java.io.Serializable;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.google.common.base.Strings;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTClaimsSet.Builder;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;

import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.api.common.client.AuthorizationGrantType;
import it.infn.mw.iam.api.common.error.NoSuchAccountError;
import it.infn.mw.iam.audit.events.tokens.AccessTokenIssuedEvent;
import it.infn.mw.iam.audit.events.tokens.IdTokenIssuedEvent;
import it.infn.mw.iam.audit.events.tokens.RefreshTokenIssuedEvent;
import it.infn.mw.iam.authn.util.Authorities;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.IamAuthenticationHolderService;
import it.infn.mw.iam.core.TokenUtils;
import it.infn.mw.iam.core.jwk.JWTSigningAndValidationService;
import it.infn.mw.iam.core.oauth.profile.JWTProfile;
import it.infn.mw.iam.core.oauth.profile.JWTProfileResolver;
import it.infn.mw.iam.core.oauth.revocation.TokenRevocationService;
import it.infn.mw.iam.core.oauth.scope.IamSystemScopeService;
import it.infn.mw.iam.core.oauth.scope.SystemScopeService;
import it.infn.mw.iam.core.oauth.scope.pdp.ScopeFilter;
import it.infn.mw.iam.core.oidc.AuthenticationTimeStamper;
import it.infn.mw.iam.core.oidc.ConnectRequestParameters;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.AuthenticationHolderEntity;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.OAuth2AccessTokenEntity;
import it.infn.mw.iam.persistence.model.OAuth2RefreshTokenEntity;
import it.infn.mw.iam.persistence.model.PKCEAlgorithm;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;
import it.infn.mw.iam.util.IdTokenHashUtils;

@SuppressWarnings("deprecation")
@Service
@Transactional
@Primary
public class IamAuthorizationServerTokenServices implements AuthorizationServerTokenServices {

  public static final String EXPIRES_IN_KEY = "expires_in";
  public static final String INVALID_PARAMETER = "Value of 'expires_in' parameter is not valid";

  public static final String MISSING_CODE_CHALLENGE_ERROR = "Expected code challenge not found";
  public static final String MISSING_CODE_VERIFIER_ERROR = "Expected code verifier not found";
  public static final String CODE_VERIFICATION_ERROR = "Code challenge and verifier do not match";
  public static final String UNEXPECTED_CODE_ERROR = "Unexpected code challenge for client";
  public static final String UNSUPPORTED_CODE_CHALLENGE_METHOD_ERROR =
      "Unsupported code challenge method";
  public static final String CLIENT_NOT_CONFIGURED =
      "PKCE not configured for this client but challenge found";

  public static final List<CodeChallengeMethod> SUPPORTED_CODE_CHALLENGE_METHODS =
      List.of(CodeChallengeMethod.S256, CodeChallengeMethod.PLAIN);

  public static final Logger LOG =
      LoggerFactory.getLogger(IamAuthorizationServerTokenServices.class);

  private final Clock clock;
  private final IamProperties iamProperties;
  private final IamOAuthAccessTokenRepository accessTokenRepo;
  private final IamOAuthRefreshTokenRepository refreshTokenRepo;
  private final IamAuthenticationHolderService authenticationHolderService;
  private final ClientService clientService;
  private final IamAccountService accountService;
  private final JWTSigningAndValidationService jwtSigningService;
  private final TokenRevocationService revocationService;
  private final SystemScopeService scopeService;
  private final JWTProfileResolver profileResolver;
  private final ApplicationEventPublisher eventPublisher;
  private final ScopeFilter scopeFilter;
  private final TokenUtils tokenUtils;

  public IamAuthorizationServerTokenServices(Clock clock, IamProperties iamProperties,
      IamOAuthAccessTokenRepository accessTokenRepo,
      IamOAuthRefreshTokenRepository refreshTokenRepo,
      IamAuthenticationHolderService authenticationHolderService, ClientService clientService,
      IamAccountService accountService, JWTSigningAndValidationService jwtSigningService,
      TokenRevocationService revocationService, SystemScopeService scopeService,
      JWTProfileResolver profileResolver, ApplicationEventPublisher eventPublisher,
      ScopeFilter scopeFilter, TokenUtils tokenUtils) {

    this.clock = clock;
    this.iamProperties = iamProperties;
    this.accessTokenRepo = accessTokenRepo;
    this.refreshTokenRepo = refreshTokenRepo;
    this.authenticationHolderService = authenticationHolderService;
    this.clientService = clientService;
    this.accountService = accountService;
    this.jwtSigningService = jwtSigningService;
    this.revocationService = revocationService;
    this.scopeService = scopeService;
    this.profileResolver = profileResolver;
    this.eventPublisher = eventPublisher;
    this.scopeFilter = scopeFilter;
    this.tokenUtils = tokenUtils;
  }

  @Override
  public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {

    throw new UnsupportedOperationException(
        "Unable to look up access token from authentication object.");
  }

  @Override
  public OAuth2AccessToken createAccessToken(OAuth2Authentication authentication)
      throws AuthenticationException {

    validate(authentication);

    OAuth2Request request = authentication.getOAuth2Request();

    ClientDetailsEntity client = clientService.findClientByClientId(request.getClientId())
      .orElseThrow(() -> new InvalidClientException("Client not found: " + request.getClientId()));

    if (!client.isActive()) {
      throw new InvalidClientException("Client is suspended: " + request.getClientId());
    }

    Optional<IamAccount> account = Optional.empty();
    if (!authentication.isClientOnly()) {
      String username = authentication.getName();
      account = accountService.findByUsername(username);
    }

    handleCodeChallenge(request, client);

    Instant iat = clock.instant();
    AuthenticationHolderEntity authHolder =
        authenticationHolderService.create(authentication, client);
    OAuth2AccessTokenEntity accessToken = new OAuth2AccessTokenEntity();
    accessToken.setClient(client);
    accessToken.setScope(computeScopes(request));
    accessToken.setExpiration(computeExpiration(request.getRequestParameters(), client, iat));
    accessToken.setAuthenticationHolder(authHolder);

    if (client.isAllowRefresh()
        && isRefreshTokenRequested(request.getGrantType(), accessToken.getScope())) {

      accessToken.setRefreshToken(createRefreshToken(client, authHolder, request.getGrantType()));
    }

    JWTProfile profile = profileResolver.resolveProfile(client.getScope());

    JWTClaimsSet atClaims =
        profile.getAccessTokenBuilder().buildAccessToken(accessToken, authentication, account, iat);

    SignedJWT signedToken = signClaims(atClaims);
    accessToken.setJwt(signedToken);
    accessToken.setTokenValueHash(tokenUtils.sha256(signedToken.serialize()));

    if (request.getScope().contains(SystemScopeService.OPENID_SCOPE) && account.isPresent()) {

      JWT idToken =
          createIdToken(client, request, Date.from(iat), account.get().getUuid(), accessToken);
      eventPublisher
        .publishEvent(new IdTokenIssuedEvent(this, idToken, authHolder, request.getGrantType()));
      accessToken.setIdToken(idToken);
    }

    if (iamProperties.getClient().isTrackLastUsed()) {
      clientService.useClient(client);
    }

    OAuth2AccessTokenEntity savedAccessToken = saveAccessToken(accessToken);
    eventPublisher
      .publishEvent(new AccessTokenIssuedEvent(this, savedAccessToken, request.getGrantType()));
    return savedAccessToken;
  }

  private boolean clientRequiresCodeChallenge(ClientDetailsEntity client) {

    return clientRequiresCodeChallengePlain(client) || clientRequiresCodeChallengeS256(client);
  }

  private boolean clientRequiresCodeChallengePlain(ClientDetailsEntity client) {

    return client.getCodeChallengeMethod() != null
        && PKCEAlgorithm.PLAIN.equals(client.getCodeChallengeMethod());
  }

  private boolean clientRequiresCodeChallengeS256(ClientDetailsEntity client) {

    return client.getCodeChallengeMethod() != null
        && PKCEAlgorithm.S256.equals(client.getCodeChallengeMethod());
  }

  private boolean clientRequiresCodeChallengeNone(ClientDetailsEntity client) {

    return client.getCodeChallengeMethod() != null
        && PKCEAlgorithm.NONE.equals(client.getCodeChallengeMethod());
  }


  private boolean isRefreshTokenRequested(String grantType, Set<String> scopes) {

    return scopes.contains(SystemScopeService.OFFLINE_ACCESS_SCOPE)
        && !grantType.equals(AuthorizationGrantType.CLIENT_CREDENTIALS.name());
  }

  private OAuth2RefreshTokenEntity createRefreshToken(ClientDetailsEntity client,
      AuthenticationHolderEntity authHolder, String grantType) {

    String jti = UUID.randomUUID().toString();
    Instant iat = clock.instant();
    Date exp = null;

    if (client.getRefreshTokenValiditySeconds() != null
        && client.getRefreshTokenValiditySeconds() > 0) {
      exp = Date.from(iat.plus(client.getRefreshTokenValiditySeconds(), ChronoUnit.SECONDS));
    }

    JWTClaimsSet.Builder refreshClaims = new JWTClaimsSet.Builder();
    refreshClaims.jwtID(jti);
    refreshClaims.issuer(iamProperties.getIssuer());
    refreshClaims.issueTime(Date.from(iat));
    refreshClaims.expirationTime(exp);
    refreshClaims.serializeNullClaims(false);
    PlainJWT refreshJwt = new PlainJWT(refreshClaims.build());

    OAuth2RefreshTokenEntity refreshToken = new OAuth2RefreshTokenEntity();
    refreshToken.setExpiration(exp);
    refreshToken.setValue(refreshJwt.serialize());
    refreshToken.setAuthenticationHolder(authHolder);
    refreshToken.setClient(client);

    refreshToken = saveRefreshToken(refreshToken);
    eventPublisher.publishEvent(new RefreshTokenIssuedEvent(this, refreshToken, grantType));

    return refreshToken;
  }

  private OAuth2RefreshTokenEntity saveRefreshToken(OAuth2RefreshTokenEntity refreshToken) {

    refreshToken.setAuthenticationHolder(
        authenticationHolderService.save(refreshToken.getAuthenticationHolder()));
    return refreshTokenRepo.save(refreshToken);
  }

  private void validate(OAuth2Authentication authentication) {

    if (authentication == null || authentication.getOAuth2Request() == null) {
      throw new AuthenticationCredentialsNotFoundException("No authentication credentials found");
    }

    if (authentication.getUserAuthentication() != null
        && authentication.getUserAuthentication().getAuthorities() != null
        && authentication.getUserAuthentication()
          .getAuthorities()
          .contains(Authorities.ROLE_PRE_AUTHENTICATED)) {
      throw new InvalidGrantException("User is not fully authenticated.");
    }
  }

  private Set<String> computeScopes(OAuth2Request request) {

    Set<String> filteredScopes = new HashSet<>();
    filteredScopes.addAll(request.getScope());
    filteredScopes.removeAll(IamSystemScopeService.RESERVED_VALUES);
    return filteredScopes;
  }

  private SignedJWT signClaims(JWTClaimsSet claims) {
    JWSAlgorithm signingAlg = jwtSigningService.getDefaultSigningAlgorithm();

    JWSHeader header = new JWSHeader(signingAlg, null, null, null, null, null, null, null, null,
        null, jwtSigningService.getDefaultSignerKeyId(), null, null);
    SignedJWT signedJWT = new SignedJWT(header, claims);

    jwtSigningService.signJwt(signedJWT);
    return signedJWT;
  }

  private void handleCodeChallenge(OAuth2Request request, ClientDetailsEntity client) {

    Map<String, Serializable> extensions = request.getExtensions();

    Object rawCodeChallenge = extensions.get(ConnectRequestParameters.CODE_CHALLENGE);

    if (rawCodeChallenge == null) {
      if (clientRequiresCodeChallenge(client)) {
        throw new InvalidRequestException(MISSING_CODE_CHALLENGE_ERROR);
      }
      return;
    }

    String codeChallenge = rawCodeChallenge.toString();

    String rawMethod =
        String.valueOf(extensions.get(ConnectRequestParameters.CODE_CHALLENGE_METHOD));
    CodeChallengeMethod codeChallengeMethod =
        rawMethod == null ? CodeChallengeMethod.PLAIN : CodeChallengeMethod.parse(rawMethod);

    if (!SUPPORTED_CODE_CHALLENGE_METHODS.contains(codeChallengeMethod)) {
      throw new InvalidRequestException(UNSUPPORTED_CODE_CHALLENGE_METHOD_ERROR);
    }

    String verifier = request.getRequestParameters().get(ConnectRequestParameters.CODE_VERIFIER);

    if (verifier == null || verifier.isBlank()) {
      throw new InvalidRequestException(MISSING_CODE_VERIFIER_ERROR);
    }

    if (CodeChallengeMethod.PLAIN.equals(codeChallengeMethod)) {
      if (clientRequiresCodeChallengeS256(client)) {
        throw new InvalidRequestException(UNEXPECTED_CODE_ERROR);
      }

      if (!codeChallenge.equals(verifier)) {
        throw new InvalidRequestException(CODE_VERIFICATION_ERROR);
      }

      LOG.debug("Plain code verified");
      return;
    }

    if (clientRequiresCodeChallengePlain(client) || clientRequiresCodeChallengeNone(client)) {
      throw new InvalidRequestException(UNEXPECTED_CODE_ERROR);
    }

    String expectedChallenge = computeS256Challenge(verifier);

    if (!codeChallenge.equals(expectedChallenge)) {
      throw new InvalidRequestException(CODE_VERIFICATION_ERROR);
    }

    LOG.debug("Hashed code verified");
  }

  private String computeS256Challenge(String verifier) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      return Base64URL.encode(digest.digest(verifier.getBytes(US_ASCII))).toString();
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 not available", e);
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

    if (!requestParameters.containsKey(EXPIRES_IN_KEY)) {
      return Optional.empty();
    }
    try {
      int value = Integer.parseInt(requestParameters.get(EXPIRES_IN_KEY));
      if (value <= 0) {
        return Optional.empty();
      }
      return Optional.of(value);
    } catch (NumberFormatException e) {
      throw new InvalidRequestException(INVALID_PARAMETER);
    }
  }

  private OAuth2AccessTokenEntity saveAccessToken(OAuth2AccessTokenEntity accessToken) {

    if (!iamProperties.getAccessToken().isStoreOnDatabase()) {
      // nothing to save
      return accessToken;
    }

    if (accessToken.getRefreshToken() == null) {
      AuthenticationHolderEntity ah =
          authenticationHolderService.save(accessToken.getAuthenticationHolder());
      accessToken.setAuthenticationHolder(ah);
    }
    return accessTokenRepo.save(accessToken);
  }

  @Override
  public OAuth2AccessTokenEntity refreshAccessToken(String refreshTokenValue,
      TokenRequest authRequest) throws AuthenticationException {

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
      account = accountService.findByUsername(username);
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
    if (isExpired(refreshToken.getExpiration())) {
      revocationService.revokeRefreshToken(refreshToken);
      throw new InvalidTokenException("Expired refresh token: " + refreshTokenValue);
    }

    Instant tokenIssueInstant = clock.instant();
    OAuth2AccessTokenEntity token = new OAuth2AccessTokenEntity();

    token.setScope(
        computeRefreshedScopes(authRequest, refreshToken.getAuthenticationHolder(), account));

    token.setClient(client);
    token.setExpiration(
        computeExpiration(authRequest.getRequestParameters(), client, tokenIssueInstant));

    if (client.isReuseRefreshToken()) {
      // if the client re-uses refresh tokens, do that
      token.setRefreshToken(refreshToken);
    } else {
      // otherwise, make a new refresh token
      token.setRefreshToken(createRefreshToken(client, authHolder, authRequest.getGrantType()));
      // clean up the old refresh token
      revocationService.revokeRefreshToken(refreshToken);
    }

    token.setAuthenticationHolder(authHolder);


    JWTClaimsSet atClaims = profile.getAccessTokenBuilder()
      .buildAccessToken(token, newOAuth2Authentication, account, tokenIssueInstant);

    SignedJWT signedToken = signClaims(atClaims);
    token.setJwt(signedToken);
    token.setTokenValueHash(tokenUtils.sha256(signedToken.serialize()));

    if (newOAuth2Request.getScope().contains(SystemScopeService.OPENID_SCOPE)
        && account.isPresent()) {

      JWT idToken = createIdToken(client, newOAuth2Request, Date.from(tokenIssueInstant),
          account.get().getUuid(), token);

      eventPublisher.publishEvent(
          new IdTokenIssuedEvent(this, idToken, authHolder, authRequest.getGrantType()));
      token.setIdToken(idToken);
    }

    if (iamProperties.getClient().isTrackLastUsed()) {
      clientService.useClient(token.getClient());
    }
    token = saveAccessToken(token);

    eventPublisher
      .publishEvent(new AccessTokenIssuedEvent(this, token, authRequest.getGrantType()));
    return token;
  }

  private boolean isExpired(Date expiration) {
    return expiration != null && clock.instant().isAfter(expiration.toInstant());
  }

  private Set<String> computeRefreshedScopes(TokenRequest authRequest,
      AuthenticationHolderEntity authHolder, Optional<IamAccount> account) {

    /* retrieve authorized scopes from refresh token */
    Set<String> authorizedScopes =
        Sets.newHashSet(authHolder.getAuthentication().getOAuth2Request().getScope());
    authorizedScopes.removeAll(IamSystemScopeService.RESERVED_VALUES);
    /* get current requested scopes, if present */
    Set<String> requestedScopes = new HashSet<>();
    if (authRequest.getScope() != null) {
      requestedScopes.addAll(authRequest.getScope());
    }
    requestedScopes.removeAll(IamSystemScopeService.RESERVED_VALUES);

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
    return scopeFilter.filterScopes(authHolder).getScope();
  }

  private OAuth2RefreshTokenEntity getRefreshToken(String refreshTokenValue) {

    return refreshTokenRepo.findByTokenValue(refreshTokenValue)
      .orElseThrow(() -> new InvalidTokenException("Invalid refresh token: token not found"));
  }

  private JWT createIdToken(ClientDetailsEntity client, OAuth2Request request, Date issueTime,
      String sub, OAuth2AccessTokenEntity accessToken) {

    JWT idToken = null;
    JWTClaimsSet.Builder idClaims = new JWTClaimsSet.Builder();

    idClaims.issuer(iamProperties.getIssuer());
    idClaims.subject(sub);
    idClaims.audience(Lists.newArrayList(client.getClientId()));
    idClaims.jwtID(UUID.randomUUID().toString());

    idClaims.issueTime(issueTime);
    handleAuthTimestamp(client, request, idClaims);

    if (client.getIdTokenValiditySeconds() != null) {
      Date expiration =
          Date.from(clock.instant().plus(Duration.ofSeconds(client.getIdTokenValiditySeconds())));
      idClaims.expirationTime(expiration);
    }

    String nonce = (String) request.getExtensions().get(ConnectRequestParameters.NONCE);
    if (!Strings.isNullOrEmpty(nonce)) {
      idClaims.claim("nonce", nonce);
    }

    Set<String> responseTypes = request.getResponseTypes();

    JWSAlgorithm signingAlg = jwtSigningService.getDefaultSigningAlgorithm();

    if (responseTypes.contains("token")) {
      Base64URL atHash = IdTokenHashUtils.getAccessTokenHash(signingAlg, accessToken);
      idClaims.claim("at_hash", atHash);
    }

    addCustomIdTokenClaims(idClaims, client, request, sub, accessToken);

    JWSHeader header =
        new JWSHeader.Builder(signingAlg).keyID(jwtSigningService.getDefaultSignerKeyId()).build();

    idClaims.claim("kid", jwtSigningService.getDefaultSignerKeyId());
    idToken = new SignedJWT(header, idClaims.build());
    jwtSigningService.signJwt((SignedJWT) idToken);

    return idToken;
  }

  private void handleAuthTimestamp(ClientDetailsEntity client, OAuth2Request request,
      JWTClaimsSet.Builder idClaims) {

    if (request.getExtensions().containsKey(ConnectRequestParameters.MAX_AGE)
        || (client.getRequireAuthTime() != null && client.getRequireAuthTime())) {

      if (request.getExtensions().get(AuthenticationTimeStamper.AUTH_TIMESTAMP) != null) {
        Long authTimestamp = Long.parseLong(
            (String) request.getExtensions().get(AuthenticationTimeStamper.AUTH_TIMESTAMP));
        if (authTimestamp != null) {
          idClaims.claim("auth_time", authTimestamp / 1000L);
        }
      } else {
        LOG.debug("Unable to find authentication timestamp while creating ID token");
      }
    }
  }

  private void addCustomIdTokenClaims(Builder idClaims, ClientDetailsEntity client,
      OAuth2Request request, String sub, OAuth2AccessTokenEntity accessToken) {

    IamAccount account =
        accountService.findByUuid(sub).orElseThrow(() -> NoSuchAccountError.forUuid(sub));

    JWTProfile profile = profileResolver.resolveProfile(client.getScope(), accessToken.getScope());

    profile.getIDTokenCustomizer()
      .customizeIdTokenClaims(idClaims, client, request, sub, accessToken, account);
  }
}
