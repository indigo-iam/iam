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
import static java.nio.charset.StandardCharsets.US_ASCII;
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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mitre.oauth2.model.AuthenticationHolderEntity;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.mitre.oauth2.model.PKCEAlgorithm;
import org.mitre.oauth2.model.SystemScope;
import org.mitre.oauth2.service.OAuth2TokenEntityService;
import org.mitre.oauth2.service.SystemScopeService;
import org.mitre.openid.connect.service.OIDCTokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.AuthenticationException;
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

import com.google.common.collect.Sets;
import com.google.common.hash.Hashing;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWT;
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
import it.infn.mw.iam.core.oauth.revocation.TokenRevocationService;
import it.infn.mw.iam.core.oauth.scope.pdp.ScopeFilter;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAuthenticationHolderRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;

@SuppressWarnings("deprecation")
@Service
public class IamTokenService implements OAuth2TokenEntityService {

  public static final String EXPIRES_IN_KEY = "expires_in";
  public static final String INVALID_PARAMETER = "Value of 'expires_in' parameter is not valid";

  public static final String CODE_VERIFICATION_ERROR = "Code challenge and verifier do not match";
  public static final String UNSUPPORTED_CODE_CHALLENGE_METHOD_ERROR =
      "Unsupported code challenge method";

  public static final Logger LOG = LoggerFactory.getLogger(IamTokenService.class);

  private final IamOAuthAccessTokenRepository accessTokenRepo;
  private final IamOAuthRefreshTokenRepository refreshTokenRepo;
  private final IamAuthenticationHolderRepository authenticationHolderRepo;
  private final ClientService clientService;
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

  private final MessageDigest sha256Digest;

  public IamTokenService(Clock clock, IamOAuthAccessTokenRepository accessTokenRepo,
      IamOAuthRefreshTokenRepository refreshTokenRepo,
      IamAuthenticationHolderRepository authenticationHolderRepo, ClientService clientService,
      IamAccountRepository accountRepository, JWTSigningAndValidationService jwtSigningService,
      TokenRevocationService revocationService, OIDCTokenService connectTokenService,
      SystemScopeService scopeService, JWTProfileResolver profileResolver,
      ApplicationEventPublisher eventPublisher, IamProperties iamProperties,
      ScopeFilter scopeFilter) throws NoSuchAlgorithmException {

    this.accessTokenRepo = accessTokenRepo;
    this.refreshTokenRepo = refreshTokenRepo;
    this.authenticationHolderRepo = authenticationHolderRepo;
    this.clientService = clientService;
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

    this.sha256Digest = MessageDigest.getInstance("SHA-256");
  }

  @Override
  public Set<OAuth2AccessTokenEntity> getAllAccessTokensForUser(String id) {

    Set<OAuth2AccessTokenEntity> results = Sets.newLinkedHashSet();
    results.addAll(accessTokenRepo.findAccessTokensForUser(id));
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

    revocationService.revokeAccessToken(accessToken);
  }

  @Override
  public void revokeRefreshToken(OAuth2RefreshTokenEntity refreshToken) {

    revocationService.revokeRefreshToken(refreshToken);
  }

  @Override
  public OAuth2AccessTokenEntity readAccessToken(String token) {

    return accessTokenRepo.findByTokenValue(sha256(token))
      .orElseThrow(() -> new InvalidTokenException("Access Token not found"));
  }

  @Override
  public OAuth2AccessTokenEntity saveAccessToken(OAuth2AccessTokenEntity accessToken) {

    AuthenticationHolderEntity ah =
        authenticationHolderRepo.save(accessToken.getAuthenticationHolder());
    accessToken.setAuthenticationHolder(ah);
    return accessTokenRepo.saveAndFlush(accessToken);
  }

  @Override
  public OAuth2Authentication loadAuthentication(String accessTokenValue)
      throws AuthenticationException {

    return readAccessToken(accessTokenValue).getAuthenticationHolder().getAuthentication();
  }

  @Override
  @Transactional(value = "defaultTransactionManager")
  public OAuth2AccessTokenEntity createAccessToken(OAuth2Authentication authentication) {

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
      account = accountRepository.findByUsername(username);
    }

    if (hasCodeChallenge(request)) {
      handleCodeChallenge(request);
    }

    Instant iat = clock.instant();
    AuthenticationHolderEntity authHolder = createAuthenticationHolder(authentication);
    OAuth2AccessTokenEntity accessToken = new OAuth2AccessTokenEntity();
    accessToken.setClient(client);
    accessToken.setScope(computeScopes(request, authentication));
    accessToken.setExpiration(computeExpiration(request.getRequestParameters(), client, iat));
    accessToken.setAuthenticationHolder(authHolder);

    if (client.isAllowRefresh()
        && isRefreshTokenRequested(request.getGrantType(), accessToken.getScope())) {

      accessToken.setRefreshToken(createRefreshToken(client, authHolder));
    }

    JWTProfile profile = profileResolver.resolveProfile(client.getScope());

    JWTClaimsSet atClaims =
        profile.getAccessTokenBuilder().buildAccessToken(accessToken, authentication, account, iat);

    accessToken.setJwt(signClaims(atClaims));
    accessToken.hashMe();

    if (request.getScope().contains(SystemScopeService.OPENID_SCOPE) && account.isPresent()) {

      accessToken.setIdToken(connectTokenService.createIdToken(client, request, Date.from(iat),
          account.get().getUuid(), accessToken));
    }

    if (iamProperties.getClient().isTrackLastUsed()) {
      clientService.useClient(client);
    }

    OAuth2AccessTokenEntity savedAccessToken = saveAccessToken(accessToken);
    eventPublisher.publishEvent(new AccessTokenIssuedEvent(this, savedAccessToken));
    return savedAccessToken;
  }

  private boolean isRefreshTokenRequested(String grantType, Set<String> scopes) {

    return scopes.contains(SystemScopeService.OFFLINE_ACCESS)
        && !grantType.equals("client_credentials");
  }

  private AuthenticationHolderEntity createAuthenticationHolder(
      OAuth2Authentication authentication) {

    AuthenticationHolderEntity authHolder = new AuthenticationHolderEntity();
    authHolder.setAuthentication(authentication);
    return authHolder;
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

  private Set<String> computeScopes(OAuth2Request request, OAuth2Authentication authentication) {

    Set<String> filteredScopes = scopeFilter.filterScopes(request.getScope(), authentication);
    Set<SystemScope> scopes = scopeService.fromStrings(filteredScopes);
    scopes = scopeService.removeReservedScopes(scopes);
    return scopeService.toStrings(scopes);
  }

  private void handleCodeChallenge(OAuth2Request request) {

    String challenge = valueOf(request.getExtensions().get(CODE_CHALLENGE));
    PKCEAlgorithm alg =
        PKCEAlgorithm.parse(valueOf(request.getExtensions().get(CODE_CHALLENGE_METHOD)));

    String verifier = request.getRequestParameters().get(CODE_VERIFIER);

    if (PKCEAlgorithm.plain.equals(alg)) {
      if (challenge.equals(verifier)) {
        LOG.debug("Plain code verified");
        return;
      }
      throw new InvalidRequestException(CODE_VERIFICATION_ERROR);
    }
    if (PKCEAlgorithm.S256.equals(alg)) {
      String hash = Base64URL.encode(sha256Digest.digest(verifier.getBytes(US_ASCII))).toString();
      if (challenge.equals(hash)) {
        LOG.debug("Hashed code verified");
        return;
      }
      throw new InvalidRequestException(CODE_VERIFICATION_ERROR);
    }
    throw new InvalidRequestException(UNSUPPORTED_CODE_CHALLENGE_METHOD_ERROR);
  }

  private boolean hasCodeChallenge(OAuth2Request request) {

    return request.getExtensions().containsKey(CODE_CHALLENGE);
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

    if (Objects.isNull(refreshTokenValue) || refreshTokenValue.isBlank()) {
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
      token.setRefreshToken(createRefreshToken(client, authHolder));
      // clean up the old refresh token
      revocationService.revokeRefreshToken(refreshToken);
    }

    token.setAuthenticationHolder(authHolder);


    JWTClaimsSet atClaims = profile.getAccessTokenBuilder()
      .buildAccessToken(token, newOAuth2Authentication, account, tokenIssueInstant);

    token.setJwt(signClaims(atClaims));
    token.hashMe();

    if (newOAuth2Request.getScope().contains(SystemScopeService.OPENID_SCOPE)
        && account.isPresent()) {

      JWT idToken = connectTokenService.createIdToken(client, newOAuth2Request,
          Date.from(tokenIssueInstant), account.get().getUuid(), token);

      token.setIdToken(idToken);
    }

    if (iamProperties.getClient().isTrackLastUsed()) {
      clientService.useClient(token.getClient());
    }
    token = saveAccessToken(token);

    eventPublisher.publishEvent(new AccessTokenIssuedEvent(this, token));
    return token;
  }

  private Set<String> computeRefreshedScopes(TokenRequest authRequest,
      AuthenticationHolderEntity authHolder, Optional<IamAccount> account) {

    /* load reserved scopes from database */
    Set<String> reservedScopes = scopeService.toStrings(scopeService.getReserved());
    /* retrieve authorized scopes from refresh token */
    Set<String> authorizedScopes =
        Sets.newHashSet(authHolder.getAuthentication().getOAuth2Request().getScope());
    authorizedScopes.removeAll(reservedScopes);
    /* get current requested scopes, if present */
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
    return scopeFilter.filterScopes(authHolder).getScope();
  }

  public static String sha256(String tokenString) {
    return Hashing.sha256().hashString(tokenString, StandardCharsets.UTF_8).toString();
  }

  @Override
  public OAuth2RefreshTokenEntity getRefreshToken(String refreshTokenValue) {

    try {
      return refreshTokenRepo.findByTokenValue(PlainJWT.parse(refreshTokenValue))
        .orElseThrow(() -> new InvalidTokenException("Invalid refresh token: token not found"));
    } catch (ParseException e) {
      throw new InvalidTokenException("Invalid refresh token: " + e.getMessage());
    }
  }

  @Override
  public List<OAuth2AccessTokenEntity> getAccessTokensForClient(ClientDetailsEntity client) {

    return accessTokenRepo.findAccessTokens(client.getId());
  }

  @Override
  public List<OAuth2RefreshTokenEntity> getRefreshTokensForClient(ClientDetailsEntity client) {

    return refreshTokenRepo.findByClientId(client.getId());
  }

  @Override
  public void clearExpiredTokens() {
    // GarbageCollector will remove them
  }

  @Override
  public OAuth2RefreshTokenEntity saveRefreshToken(OAuth2RefreshTokenEntity refreshToken) {

    refreshToken.setAuthenticationHolder(
        authenticationHolderRepo.save(refreshToken.getAuthenticationHolder()));
    return refreshTokenRepo.save(refreshToken);
  }

  @Override
  public OAuth2AccessTokenEntity getAccessToken(OAuth2Authentication authentication) {

    throw new UnsupportedOperationException(
        "Unable to look up access token from authentication object.");
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
