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

import static it.infn.mw.iam.core.oauth.IamOAuth2ParameterNames.CODE_CHALLENGE;
import static it.infn.mw.iam.core.oauth.IamOAuth2ParameterNames.CODE_CHALLENGE_METHOD;
import static it.infn.mw.iam.core.oauth.IamOAuth2ParameterNames.CODE_VERIFIER;
import static java.lang.String.valueOf;
import static java.nio.charset.StandardCharsets.US_ASCII;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

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

import com.google.common.base.Strings;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTClaimsSet.Builder;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.api.common.error.NoSuchAccountError;
import it.infn.mw.iam.audit.events.tokens.AccessTokenIssuedEvent;
import it.infn.mw.iam.audit.events.tokens.RefreshTokenIssuedEvent;
import it.infn.mw.iam.authn.util.Authorities;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.jwt.ClientKeyCacheService;
import it.infn.mw.iam.core.jwt.JwtEncryptionAndDecryptionService;
import it.infn.mw.iam.core.jwt.JwtSigningAndValidationService;
import it.infn.mw.iam.core.jwt.SymmetricKeyJWTValidatorCacheService;
import it.infn.mw.iam.core.oauth.IamOAuth2ParameterNames;
import it.infn.mw.iam.core.oauth.profile.JWTProfile;
import it.infn.mw.iam.core.oauth.profile.JWTProfileResolver;
import it.infn.mw.iam.core.oauth.revocation.TokenRevocationService;
import it.infn.mw.iam.core.oauth.scope.SystemScopeService;
import it.infn.mw.iam.core.oauth.scope.pdp.ScopeFilter;
import it.infn.mw.iam.core.web.util.AuthenticationTimeStamper;
import it.infn.mw.iam.persistence.model.AuthenticationHolderEntity;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.OAuth2AccessTokenEntity;
import it.infn.mw.iam.persistence.model.OAuth2RefreshTokenEntity;
import it.infn.mw.iam.persistence.model.PKCEAlgorithm;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAuthenticationHolderRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;
import it.infn.mw.iam.util.IdTokenHashUtils;

@SuppressWarnings("deprecation")
@Service
public class IamTokenService implements OAuth2TokenEntityService {

  record CodeChallenge(String code, PKCEAlgorithm method, String verifier) {
  }

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
  private final JwtSigningAndValidationService jwtSigningService;
  private final TokenRevocationService revocationService;
  private final SystemScopeService scopeService;
  private final JWTProfileResolver profileResolver;
  private final ApplicationEventPublisher eventPublisher;
  private final IamProperties iamProperties;
  private final ScopeFilter scopeFilter;
  private final Clock clock;
  private final ClientKeyCacheService encrypters;
  private final SymmetricKeyJWTValidatorCacheService symmetricCacheService;

  private final MessageDigest sha256Digest;

  public IamTokenService(Clock clock, IamOAuthAccessTokenRepository accessTokenRepo,
      IamOAuthRefreshTokenRepository refreshTokenRepo,
      IamAuthenticationHolderRepository authenticationHolderRepo, ClientService clientService,
      IamAccountRepository accountRepository, JwtSigningAndValidationService jwtSigningService,
      TokenRevocationService revocationService, SystemScopeService scopeService,
      JWTProfileResolver profileResolver, ApplicationEventPublisher eventPublisher,
      IamProperties iamProperties, ScopeFilter scopeFilter, ClientKeyCacheService encrypters,
      SymmetricKeyJWTValidatorCacheService symmetricCacheService) throws NoSuchAlgorithmException {

    this.accessTokenRepo = accessTokenRepo;
    this.refreshTokenRepo = refreshTokenRepo;
    this.authenticationHolderRepo = authenticationHolderRepo;
    this.clientService = clientService;
    this.accountRepository = accountRepository;
    this.jwtSigningService = jwtSigningService;
    this.revocationService = revocationService;
    this.scopeService = scopeService;
    this.profileResolver = profileResolver;
    this.eventPublisher = eventPublisher;
    this.iamProperties = iamProperties;
    this.scopeFilter = scopeFilter;
    this.clock = clock;
    this.encrypters = encrypters;
    this.symmetricCacheService = symmetricCacheService;

    this.sha256Digest = MessageDigest.getInstance("SHA-256");
  }

  @Override
  public Set<OAuth2AccessTokenEntity> getAllAccessTokensForUser(String id) {

    Set<OAuth2AccessTokenEntity> results = new LinkedHashSet<>();
    results.addAll(accessTokenRepo.findAccessTokensForUser(id));
    return results;
  }

  @Override
  public Set<OAuth2RefreshTokenEntity> getAllRefreshTokensForUser(String id) {

    Set<OAuth2RefreshTokenEntity> results = new LinkedHashSet<>();
    results.addAll(refreshTokenRepo.findRefreshTokensForUser(id));
    return results;
  }

  @Override
  public OAuth2Authentication loadAuthentication(String accessTokenValue)
      throws AuthenticationException {

    return readAccessToken(accessTokenValue).getAuthenticationHolder().getAuthentication();
  }

  private ClientDetailsEntity getClient(OAuth2Request request) {

    ClientDetailsEntity client = clientService.findClientByClientId(request.getClientId())
      .orElseThrow(() -> new InvalidClientException("Client not found: " + request.getClientId()));

    if (!client.isActive()) {
      throw new InvalidClientException("Client is suspended: " + client.getClientId());
    }

    return client;
  }

  private Optional<IamAccount> getAccountIfPresent(OAuth2Authentication authentication) {

    Optional<IamAccount> account = Optional.empty();
    if (!authentication.isClientOnly()) {
      String username = authentication.getName();
      account = accountRepository.findByUsername(username);
    }
    return account;
  }

  @Override
  public OAuth2AccessTokenEntity readAccessToken(String accessTokenValue) {

    String hValue = sha256(accessTokenValue);
    OAuth2AccessTokenEntity accessToken = accessTokenRepo.findByTokenValue(hValue)
      .orElseThrow(() -> new InvalidTokenException("Access token not found"));

    if (accessToken.isExpired()) {
      throw new InvalidTokenException("The access token is expired");
    }

    return accessToken;
  }

  @Override
  @Transactional(value = "defaultTransactionManager")
  public OAuth2AccessTokenEntity createAccessToken(OAuth2Authentication authentication) {

    validate(authentication);
    OAuth2Request request = authentication.getOAuth2Request();
    ClientDetailsEntity client = getClient(request);
    Optional<IamAccount> account = getAccountIfPresent(authentication);

    Optional<CodeChallenge> codeChallenge = getCodeChallenge(request);
    if (codeChallenge.isPresent()) {
      handleCodeChallenge(codeChallenge.get());
    }

    AuthenticationHolderEntity authHolder = new AuthenticationHolderEntity(client, authentication);

    Set<String> authorizedScopes =
        computeScopes(authentication.getOAuth2Request().getScope(), account);
    authHolder.setScope(authorizedScopes);

    OAuth2AccessTokenEntity accessToken =
        createAccessToken(client, authHolder, authentication, account, authorizedScopes);

    if (client.isAllowRefresh()
        && isRefreshTokenRequested(request.getGrantType(), accessToken.getScope())) {

      OAuth2RefreshTokenEntity refreshToken = createRefreshToken(client, authHolder, accessToken);
      accessToken.setRefreshToken(refreshToken);
      authHolder.addRefreshToken(refreshToken);
    }

    if (iamProperties.getClient().isTrackLastUsed()) {
      clientService.useClient(client);
    }

    AuthenticationHolderEntity savedAuthHolder = save(authHolder);
    return savedAuthHolder.getAccessTokens().stream().findFirst().get();
  }

  private OAuth2AccessTokenEntity createAccessToken(ClientDetailsEntity client,
      AuthenticationHolderEntity authHolder, OAuth2Authentication authentication,
      Optional<IamAccount> account, Set<String> scopes) {

    Instant iat = clock.instant();
    Date expiration = computeExpiration(authentication.getOAuth2Request(), client, iat);

    OAuth2AccessTokenEntity accessToken = new OAuth2AccessTokenEntity(client, authHolder);
    accessToken.setScope(scopes);
    accessToken.setExpiration(expiration);

    JWTProfile profile = profileResolver.resolveProfile(client.getScope());
    JWTClaimsSet atClaims =
        profile.getAccessTokenBuilder().buildAccessToken(accessToken, authentication, account, iat);

    accessToken.setTokenValue(signClaims(atClaims).serialize());

    if (scopes.contains(SystemScopeService.OPENID_SCOPE) && account.isPresent()) {

      JWT idToken = createIdToken(client, authentication.getOAuth2Request(), Date.from(iat),
          account.get().getUuid(), accessToken);
      accessToken.setIdToken(idToken);
    }
    authHolder.addAccessToken(accessToken);

    return accessToken;
  }

  private boolean isRefreshTokenRequested(String grantType, Set<String> scopes) {

    return scopes.contains(SystemScopeService.OFFLINE_ACCESS)
        && !grantType.equals("client_credentials");
  }

  private Date computeExpiration(OAuth2Request request, ClientDetailsEntity client,
      Instant tokenIssueInstant) {

    Optional<Integer> expiresIn = getExpiresIn(request);
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

  private Optional<Integer> getExpiresIn(OAuth2Request request) {

    Map<String, String> requestParameters = request.getRequestParameters();
    if (request.isRefresh()) {
      requestParameters = request.getRefreshTokenRequest().getRequestParameters();
    }
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

  // private Set<String> getScopes(AuthenticationHolderEntity authHolder,
  // Optional<IamAccount> account) {
  //
  // Set<String> authorizedScopes = authHolder.getAuthentication().getOAuth2Request().getScope();
  // Set<String> filteredScopes = new HashSet<>();
  // if (account.isPresent()) {
  // filteredScopes.addAll(scopeFilter.filterScopes(authorizedScopes, account.get()));
  // } else {
  // filteredScopes.addAll(authorizedScopes);
  // }
  // return scopeService
  // .toStrings(scopeService.removeReservedScopes(scopeService.fromStrings(filteredScopes)));
  // }

  private Set<String> refreshScopes(OAuth2Authentication authn, Optional<IamAccount> account) {

    Set<String> authorizedScopes = authn.getOAuth2Request().getScope();
    Set<String> requestedScopes = authn.getOAuth2Request().getRefreshTokenRequest().getScope();
    // Set<String> authorizedScopes =
    // oldAuthHolder.getAuthentication().getOAuth2Request().getScope();
    // Set<String> requestedScopes =
    // newAuthHolder.getAuthentication().getOAuth2Request().getScope();
    if (requestedScopes == null || requestedScopes.isEmpty()) {
      requestedScopes = new HashSet<>(authorizedScopes);
    } else {
      /* Check for up-scoping */
      if (!scopeService.scopesMatch(authorizedScopes, requestedScopes)) {
        String errorMsg = "Up-scoping is not allowed.";
        LOG.error(errorMsg);
        throw new InvalidScopeException(errorMsg);
      }
    }
    if (account.isPresent()) {
      return scopeFilter.filterScopes(requestedScopes, account.get());
    }
    return requestedScopes;
  }


  private Set<String> computeScopes(Set<String> requestedScopes, Optional<IamAccount> account) {

    Set<String> filteredScopes = new HashSet<>();
    if (account.isPresent()) {
      filteredScopes.addAll(scopeFilter.filterScopes(requestedScopes, account.get()));
    } else {
      filteredScopes.addAll(requestedScopes);
    }
    return scopeService
      .toStrings(scopeService.removeReservedScopes(scopeService.fromStrings(filteredScopes)));
  }

  private void handleCodeChallenge(CodeChallenge codeChallenge) {

    if (PKCEAlgorithm.plain.equals(codeChallenge.method)) {
      if (codeChallenge.code.equals(codeChallenge.verifier)) {
        LOG.debug("Plain code verified");
        return;
      }
      throw new InvalidRequestException(CODE_VERIFICATION_ERROR);
    }
    if (PKCEAlgorithm.S256.equals(codeChallenge.method)) {
      String hash = Base64URL.encode(sha256Digest.digest(codeChallenge.verifier.getBytes(US_ASCII)))
        .toString();
      if (codeChallenge.code.equals(hash)) {
        LOG.debug("Hashed code verified");
        return;
      }
      throw new InvalidRequestException(CODE_VERIFICATION_ERROR);
    }
    throw new InvalidRequestException(UNSUPPORTED_CODE_CHALLENGE_METHOD_ERROR);
  }

  private Optional<CodeChallenge> getCodeChallenge(OAuth2Request request) {

    if (request.getRequestParameters().containsKey(CODE_CHALLENGE)
        && request.getRequestParameters().containsKey(CODE_CHALLENGE_METHOD)
        && request.getRequestParameters().containsKey(CODE_VERIFIER)) {

      return Optional
        .of(new CodeChallenge(valueOf(request.getRequestParameters().get(CODE_CHALLENGE)),
            PKCEAlgorithm.parse(valueOf(request.getRequestParameters().get(CODE_CHALLENGE_METHOD))),
            valueOf(request.getRequestParameters().get(CODE_VERIFIER))));
    }
    if (request.getExtensions().containsKey(CODE_CHALLENGE)
        && request.getExtensions().containsKey(CODE_CHALLENGE_METHOD)
        && request.getExtensions().containsKey(CODE_VERIFIER)) {

      return Optional
        .of(new CodeChallenge(valueOf(request.getRequestParameters().get(CODE_CHALLENGE)),
            PKCEAlgorithm.parse(valueOf(request.getRequestParameters().get(CODE_CHALLENGE_METHOD))),
            valueOf(request.getRequestParameters().get(CODE_VERIFIER))));
    }
    return Optional.empty();
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

  public OAuth2RefreshTokenEntity createRefreshToken(ClientDetailsEntity client,
      AuthenticationHolderEntity authHolder, OAuth2AccessTokenEntity accessToken) {

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

    OAuth2RefreshTokenEntity refreshToken =
        new OAuth2RefreshTokenEntity(client, authHolder, accessToken, refreshJwt);
    refreshToken.setExpiration(exp);

    return refreshToken;
  }

  @Override
  public OAuth2AccessTokenEntity refreshAccessToken(String refreshTokenValue,
      TokenRequest authRequest) {

    if (Objects.isNull(refreshTokenValue) || refreshTokenValue.isBlank()) {
      throw new InvalidTokenException("Invalid refresh token: null or empty value");
    }

    ClientDetailsEntity requestingClient =
        clientService.findClientByClientId(authRequest.getClientId())
          .orElseThrow(
              () -> new IllegalStateException("Invalid requesting client id: client not found"));

    /* client validation */
    if (!requestingClient.isActive()) {
      throw new InvalidClientException("Suspended client '" + requestingClient.getClientId() + "'");
    }
    if (!requestingClient.isAllowRefresh()) {
      throw new InvalidClientException("Client '" + requestingClient.getClientId()
          + "' does not allow refreshing access token!");
    }

    OAuth2RefreshTokenEntity refreshToken = getRefreshToken(refreshTokenValue);

    /* refresh token validation */
    if (refreshToken.isExpired()) {
      revocationService.revokeRefreshToken(refreshToken);
      throw new InvalidTokenException("Expired refresh token: " + refreshTokenValue);
    }

    ClientDetailsEntity client = refreshToken.getClient();

    if (!requestingClient.getClientId().equals(client.getClientId())) {
      revocationService.revokeRefreshToken(refreshToken);
      throw new InvalidClientException("Client does not own the presented refresh token");
    }

    AuthenticationHolderEntity authHolder = refreshToken.getAuthenticationHolder();

    OAuth2Request newOAuth2Request =
        authHolder.getAuthentication().getOAuth2Request().refresh(authRequest);
    OAuth2Authentication newOAuth2Authentication =
        new OAuth2Authentication(newOAuth2Request, authHolder.getUserAuth());

    Optional<IamAccount> account = Optional.empty();
    if (!newOAuth2Authentication.isClientOnly()) {
      String username = newOAuth2Authentication.getName();
      account = accountRepository.findByUsername(username);
    }

    // Instant tokenIssueInstant = clock.instant();

    AuthenticationHolderEntity newAuthHolder =
        new AuthenticationHolderEntity(requestingClient, newOAuth2Authentication);

    Set<String> refreshedScopes = refreshScopes(newOAuth2Authentication, account);
    newAuthHolder.setScope(refreshedScopes);

    OAuth2AccessTokenEntity accessToken = createAccessToken(requestingClient, newAuthHolder,
        newOAuth2Authentication, account, refreshedScopes);

    if (client.isReuseRefreshToken()) {

      refreshToken.addAccessToken(accessToken);
      accessToken.setRefreshToken(refreshToken);

    } else {

      OAuth2RefreshTokenEntity newRefreshToken =
          createRefreshToken(client, authHolder, accessToken);
      accessToken.setRefreshToken(newRefreshToken);
      authHolder.getRefreshTokens().remove(refreshToken);
      revocationService.revokeRefreshToken(refreshToken);
      authenticationHolderRepo.save(authHolder);
    }

    accessToken.setAuthenticationHolder(newAuthHolder);

    if (iamProperties.getClient().isTrackLastUsed()) {
      clientService.useClient(newAuthHolder.getClient());
    }

    AuthenticationHolderEntity savedAuthHolder = save(newAuthHolder);
    return savedAuthHolder.getAccessTokens().stream().findFirst().get();
  }

  @Override
  public OAuth2RefreshTokenEntity getRefreshToken(String refreshTokenValue) {

    return refreshTokenRepo.findByTokenValue(refreshTokenValue)
      .orElseThrow(() -> new InvalidTokenException("Invalid refresh token: token not found"));
  }

  @Override
  public List<OAuth2AccessTokenEntity> getAccessTokensForClient(ClientDetailsEntity client) {

    return accessTokenRepo.findAccessTokens(client.getId());
  }

  @Override
  public List<OAuth2RefreshTokenEntity> getRefreshTokensForClient(ClientDetailsEntity client) {

    return refreshTokenRepo.findByClientId(client.getId());
  }

  // public OAuth2RefreshTokenEntity saveRefreshToken(OAuth2RefreshTokenEntity refreshToken) {
  //
  // AuthenticationHolderEntity ah =
  // authenticationHolderRepo.save(refreshToken.getAuthenticationHolder());
  // refreshToken.setAuthenticationHolder(ah);
  // return refreshTokenRepo.saveAndFlush(refreshToken);
  // }

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

  public static String sha256(String tokenString) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest(tokenString.getBytes(StandardCharsets.UTF_8));
      return bytesToHex(hash);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  private static String bytesToHex(byte[] bytes) {
    StringBuilder sb = new StringBuilder(bytes.length * 2);
    for (byte b : bytes) {
      sb.append(String.format("%02x", b));
    }
    return sb.toString();
  }

  @Override
  public JWT createIdToken(ClientDetailsEntity client, OAuth2Request request, Date issueTime,
      String sub, OAuth2AccessTokenEntity accessToken) {

    JWSAlgorithm signingAlg = jwtSigningService.getDefaultSigningAlgorithm();

    if (client.getIdTokenSignedResponseAlg() != null) {
      signingAlg = client.getIdTokenSignedResponseAlg();
    }

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
          new Date(System.currentTimeMillis() + (client.getIdTokenValiditySeconds() * 1000L));
      idClaims.expirationTime(expiration);
    }

    String nonce = (String) request.getExtensions().get(IamOAuth2ParameterNames.NONCE);
    if (!Strings.isNullOrEmpty(nonce)) {
      idClaims.claim("nonce", nonce);
    }

    Set<String> responseTypes = request.getResponseTypes();

    if (responseTypes.contains("token")) {
      Base64URL atHash = IdTokenHashUtils.getAccessTokenHash(signingAlg, accessToken);
      idClaims.claim("at_hash", atHash);
    }

    addCustomIdTokenClaims(idClaims, client, request, sub, accessToken);

    if (clientWantsEncryptedIdTokens(client)) {

      JwtEncryptionAndDecryptionService encrypter =
          Optional.ofNullable(encrypters.getEncrypter(client)).orElseThrow();

      JWEHeader header = new JWEHeader.Builder(client.getIdTokenEncryptedResponseAlg(),
          client.getIdTokenEncryptedResponseEnc()).build();
      idToken = new EncryptedJWT(header, idClaims.build());
      encrypter.encryptJwt((JWEObject) idToken);

    } else {

      JWSHeader header =
          new JWSHeader.Builder(signingAlg).keyID(jwtSigningService.getDefaultSignerKeyId())
            .build();

      if (JWSAlgorithm.Family.HMAC_SHA.contains(signingAlg)) {
        idToken = new SignedJWT(header, idClaims.build());
        JwtSigningAndValidationService signer =
            Optional.ofNullable(symmetricCacheService.getSymmetricValidator(client)).orElseThrow();
        signer.signJwt((SignedJWT) idToken);
      } else {
        idClaims.claim("kid", jwtSigningService.getDefaultSignerKeyId());
        idToken = new SignedJWT(header, idClaims.build());
        jwtSigningService.signJwt((SignedJWT) idToken);
      }
    }

    return idToken;
  }

  private boolean clientWantsEncryptedIdTokens(ClientDetailsEntity client) {

    return client.getIdTokenEncryptedResponseAlg() != null
        && !client.getIdTokenEncryptedResponseAlg().equals(Algorithm.NONE)
        && client.getIdTokenEncryptedResponseEnc() != null
        && !client.getIdTokenEncryptedResponseEnc().equals(Algorithm.NONE)
        && (!Strings.isNullOrEmpty(client.getJwksUri()) || client.getJwks() != null);
  }

  private void addCustomIdTokenClaims(Builder idClaims, ClientDetailsEntity client,
      OAuth2Request request, String sub, OAuth2AccessTokenEntity accessToken) {

    IamAccount account =
        accountRepository.findByUuid(sub).orElseThrow(() -> NoSuchAccountError.forUuid(sub));

    JWTProfile profile = profileResolver.resolveProfile(client.getScope(), accessToken.getScope());

    profile.getIDTokenCustomizer()
      .customizeIdTokenClaims(idClaims, client, request, sub, accessToken, account);
  }


  private void handleAuthTimestamp(ClientDetailsEntity client, OAuth2Request request,
      JWTClaimsSet.Builder idClaims) {

    if (request.getExtensions().containsKey(IamOAuth2ParameterNames.MAX_AGE)
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

  @Override
  public OAuth2AccessTokenEntity createRegistrationAccessToken(ClientDetailsEntity client) {

    return buildRegistrationAccessToken(client,
        Sets.newHashSet(SystemScopeService.REGISTRATION_TOKEN_SCOPE));
  }

  @Override
  public OAuth2AccessTokenEntity createResourceAccessToken(ClientDetailsEntity client) {

    return buildRegistrationAccessToken(client,
        Sets.newHashSet(SystemScopeService.RESOURCE_TOKEN_SCOPE));
  }

  @Override
  public OAuth2AccessTokenEntity rotateRegistrationAccessTokenForClient(
      ClientDetailsEntity client) {

    accessTokenRepo.findRegistrationToken(client.getId())
      .ifPresent(revocationService::revokeAccessToken);
    return createRegistrationAccessToken(client);
  }

  @Override
  public OAuth2AccessTokenEntity rotateResourceAccessTokenForClient(ClientDetailsEntity client) {

    accessTokenRepo.findResourceToken(client.getId())
      .ifPresent(revocationService::revokeAccessToken);
    return createResourceAccessToken(client);
  }

  private OAuth2AccessTokenEntity buildRegistrationAccessToken(ClientDetailsEntity client,
      Set<String> scope) {

    Map<String, String> authorizationParameters = Maps.newHashMap();
    OAuth2Request clientAuth = new OAuth2Request(authorizationParameters, client.getClientId(),
        Sets.newHashSet(Authorities.ROLE_CLIENT), true, scope, null, null, null, null);

    OAuth2Authentication authentication = new OAuth2Authentication(clientAuth, null);

    AuthenticationHolderEntity authHolder = new AuthenticationHolderEntity(client, authentication);

    OAuth2AccessTokenEntity regToken = new OAuth2AccessTokenEntity(client, authHolder);
    regToken.setScope(scope);

    JWTClaimsSet claims =
        new JWTClaimsSet.Builder().audience(Lists.newArrayList(client.getClientId()))
          .issuer(iamProperties.getIssuer())
          .issueTime(Date.from(clock.instant()))
          .jwtID(UUID.randomUUID().toString())
          .build();

    JWSAlgorithm signingAlg = jwtSigningService.getDefaultSigningAlgorithm();
    JWSHeader header =
        new JWSHeader.Builder(signingAlg).keyID(jwtSigningService.getDefaultSignerKeyId()).build();
    SignedJWT signedToken = new SignedJWT(header, claims);

    jwtSigningService.signJwt(signedToken);
    regToken.setTokenJwtValue(signedToken);

    authHolder.addAccessToken(regToken);

    return save(authHolder).getAccessTokens().stream().findFirst().get();
  }

  private AuthenticationHolderEntity save(AuthenticationHolderEntity authHolder) {

    AuthenticationHolderEntity savedAuthHolder = authenticationHolderRepo.saveAndFlush(authHolder);
    eventPublisher.publishEvent(new AccessTokenIssuedEvent(this,
        savedAuthHolder.getAccessTokens().stream().findFirst().get()));
    if (!savedAuthHolder.getRefreshTokens().isEmpty()) {
      eventPublisher.publishEvent(new RefreshTokenIssuedEvent(this,
          savedAuthHolder.getRefreshTokens().stream().findFirst().get()));
    }
    return savedAuthHolder;
  }


}
