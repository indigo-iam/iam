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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDate;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.google.common.base.Strings;
import com.google.common.collect.Sets;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;

import it.infn.mw.iam.api.client.management.service.OAuth2TokenService;
import it.infn.mw.iam.audit.events.tokens.AccessTokenIssuedEvent;
import it.infn.mw.iam.audit.events.tokens.RefreshTokenIssuedEvent;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.scope.pdp.ScopeFilter;
import it.infn.mw.iam.persistence.model.IamAccessToken;
import it.infn.mw.iam.persistence.model.IamClient;
import it.infn.mw.iam.persistence.model.IamRefreshToken;
import it.infn.mw.iam.persistence.model.PKCEAlgorithm;
import it.infn.mw.iam.persistence.repository.IamAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.IamRefreshTokenRepository;

@SuppressWarnings("deprecation")
@Service("defaultOAuth2ProviderTokenService")
@Primary
public class IamTokenService implements OAuth2TokenService {

  public static final Logger LOG = LoggerFactory.getLogger(IamTokenService.class);

  private final IamAccessTokenRepository accessTokenRepo;
  private final IamRefreshTokenRepository refreshTokenRepo;
  private final ApplicationEventPublisher eventPublisher;
  private final IamProperties iamProperties;
  private final ScopeFilter scopeFilter;

  private IamAccessTokenRepository accessTokenRepository;
  private IamRefreshTokenRepository refreshTokenRepository;
  private AuthenticationHolderRepository authenticationHolderRepository;
  private IamClientService clientDetailsService;
  private TokenEnhancer tokenEnhancer;
  private SystemScopeService scopeService;
  private ApprovedSiteService approvedSiteService;

  public IamTokenService(IamAccessTokenRepository atRepo,
      IamRefreshTokenRepository rtRepo, ApplicationEventPublisher publisher,
      IamProperties iamProperties, ScopeFilter scopeFilter) {

    this.accessTokenRepo = atRepo;
    this.refreshTokenRepo = rtRepo;
    this.eventPublisher = publisher;
    this.iamProperties = iamProperties;
    this.scopeFilter = scopeFilter;
  }
  
  public List<IamAccessToken> getAllAccessTokensForUser(String userName) {
    return accessTokenRepository.findValidAccessTokensForUser(userName, new Date());
  }

  @Override
  public List<IamRefreshToken> getAllRefreshTokensForUser(String userName) {
    return refreshTokenRepository.findValidRefreshTokensForUser(userName, new Date());
  }

  @Override
  public IamAccessToken getAccessTokenById(Long id) {
    return clearExpiredAccessToken(tokenRepository.getAccessTokenById(id));
  }

  @Override
  public IamRefreshToken getRefreshTokenById(Long id) {
    return clearExpiredRefreshToken(tokenRepository.getRefreshTokenById(id));
  }

  /**
   * Utility function to delete an access token that's expired before returning it.
   * 
   * @param token the token to check
   * @return null if the token is null or expired, the input token (unchanged) if it hasn't
   */
  private IamAccessToken clearExpiredAccessToken(IamAccessToken token) {
    if (token == null) {
      return null;
    } else if (token.isExpired()) {
      // immediately revoke expired token
      logger.debug("Clearing expired access token: " + token.getValue());
      revokeAccessToken(token);
      return null;
    } else {
      return token;
    }
  }

  /**
   * Utility function to delete a refresh token that's expired before returning it.
   * 
   * @param token the token to check
   * @return null if the token is null or expired, the input token (unchanged) if it hasn't
   */
  private IamRefreshToken clearExpiredRefreshToken(IamRefreshToken token) {
    if (token == null) {
      return null;
    } else if (token.isExpired()) {
      // immediately revoke expired token
      logger.debug("Clearing expired refresh token: " + token.getValue());
      revokeRefreshToken(token);
      return null;
    } else {
      return token;
    }
  }

  @Override
  @Transactional(value = "defaultTransactionManager")
  public IamAccessToken createAccessToken(OAuth2Authentication authentication)
      throws AuthenticationException {

    if (authentication != null && authentication.getOAuth2Request() != null) {
      // look up our client
      OAuth2Request request = authentication.getOAuth2Request();

      IamClient client = clientDetailsService.loadClientByClientId(request.getClientId());

      if (client == null) {
        throw new InvalidClientException("Client not found: " + request.getClientId());
      }

      if (!client.isActive()) {
        throw new InvalidClientException("Client is suspended: " + request.getClientId());
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
            logger.error("Unknown algorithm for PKCE digest", e);
          }
        }

      }

      IamAccessToken token = new IamAccessToken();// accessTokenFactory.createNewAccessToken();

      // attach the client
      token.setClient(client);

      // inherit the scope from the auth, but make a new set so it is
      // not unmodifiable. Unmodifiables don't play nicely with Eclipselink, which
      // wants to use the clone operation.
      Set<SystemScope> scopes = scopeService.fromStrings(request.getScope());

      // remove any of the special system scopes
      scopes = scopeService.removeReservedScopes(scopes);

      token.setScope(scopeService.toStrings(scopes));

      // make it always expire
      if (client.getAccessTokenValiditySeconds() != null
          && client.getAccessTokenValiditySeconds() > 0) {
        Date expiration =
            new Date(System.currentTimeMillis() + (client.getAccessTokenValiditySeconds() * 1000L));

        token.setExpiration(expiration);
      }

      // attach the authorization so that we can look it up later
      AuthenticationHolderEntity authHolder = new AuthenticationHolderEntity();
      authHolder.setAuthentication(authentication);
      authHolder = authenticationHolderRepository.save(authHolder);

      token.setAuthenticationHolder(authHolder);

      // attach a refresh token, if this client is allowed to request them, the user gets the
      // offline scope and grant type differs from client credentials
      if (client.isAllowRefresh() && token.getScope().contains(SystemScopeService.OFFLINE_ACCESS)
          && !request.getGrantType().equals("client_credentials")) {
        IamRefreshToken savedRefreshToken = createRefreshToken(client, authHolder);

        token.setRefreshToken(savedRefreshToken);
      }

      // Add approved site reference, if any
      OAuth2Request originalAuthRequest = authHolder.getAuthentication().getOAuth2Request();

      if (originalAuthRequest.getExtensions() != null
          && originalAuthRequest.getExtensions().containsKey("approved_site")) {

        Long apId =
            Long.parseLong((String) originalAuthRequest.getExtensions().get("approved_site"));
        ApprovedSite ap = approvedSiteService.getById(apId);

        token.setApprovedSite(ap);
      }

      IamAccessToken enhancedToken =
          (IamAccessToken) tokenEnhancer.enhance(token, authentication);

      IamAccessToken savedToken = saveAccessToken(enhancedToken);

      if (savedToken.getRefreshToken() != null) {
        tokenRepository.saveRefreshToken(savedToken.getRefreshToken());
      }

      return savedToken;
    }

    throw new AuthenticationCredentialsNotFoundException("No authentication credentials found");
  }


  public IamRefreshToken createRefreshToken(IamClient client,
      AuthenticationHolderEntity authHolder) {
    IamRefreshToken refreshToken = new IamRefreshToken(); // refreshTokenFactory.createNewRefreshToken();
    JWTClaimsSet.Builder refreshClaims = new JWTClaimsSet.Builder();


    // set RT's expiration value, otherwise leaves null
    if (client.getRefreshTokenValiditySeconds() != null
        && client.getRefreshTokenValiditySeconds() > 0) {
      Date expiration =
          new Date(System.currentTimeMillis() + (client.getRefreshTokenValiditySeconds() * 1000L));
      refreshToken.setExpiration(expiration);
      refreshClaims.expirationTime(expiration);
    }

    // set a random identifier
    refreshClaims.jwtID(UUID.randomUUID().toString());

    // TODO: add issuer fields, signature to JWT

    PlainJWT refreshJwt = new PlainJWT(refreshClaims.build());
    refreshToken.setJwt(refreshJwt);

    // Add the authentication
    refreshToken.setAuthenticationHolder(authHolder);
    refreshToken.setClient(client);

    // save the token first so that we can set it to a member of the access token (NOTE: is this
    // step necessary?)
    IamRefreshToken savedRefreshToken = tokenRepository.saveRefreshToken(refreshToken);
    return savedRefreshToken;
  }

  @Override
  @Transactional(value = "defaultTransactionManager")
  public IamAccessToken refreshAccessToken(String refreshTokenValue,
      TokenRequest authRequest) throws AuthenticationException {

    if (Strings.isNullOrEmpty(refreshTokenValue)) {
      // throw an invalid token exception if there's no refresh token value at all
      throw new InvalidTokenException("Invalid refresh token: " + refreshTokenValue);
    }

    IamRefreshToken refreshToken =
        clearExpiredRefreshToken(tokenRepository.getRefreshTokenByValue(refreshTokenValue));

    if (refreshToken == null) {
      // throw an invalid token exception if we couldn't find the token
      throw new InvalidTokenException("Invalid refresh token: " + refreshTokenValue);
    }

    IamClient client = refreshToken.getClient();

    AuthenticationHolderEntity authHolder = refreshToken.getAuthenticationHolder();

    // make sure that the client requesting the token is the one who owns the refresh token
    IamClient requestingClient =
        clientDetailsService.loadClientByClientId(authRequest.getClientId());
    if (!client.getClientId().equals(requestingClient.getClientId())) {
      tokenRepository.removeRefreshToken(refreshToken);
      throw new InvalidClientException("Client does not own the presented refresh token");
    }

    if (!client.isActive()) {
      throw new InvalidClientException("Client is suspended: " + authRequest.getClientId());
    }

    // Make sure this client allows access token refreshing
    if (!client.isAllowRefresh()) {
      throw new InvalidClientException("Client does not allow refreshing access token!");
    }

    // clear out any access tokens
    if (client.isClearAccessTokensOnRefresh()) {
      tokenRepository.clearAccessTokensForRefreshToken(refreshToken);
    }

    if (refreshToken.isExpired()) {
      tokenRepository.removeRefreshToken(refreshToken);
      throw new InvalidTokenException("Expired refresh token: " + refreshTokenValue);
    }

    IamAccessToken token = new IamAccessToken();

    Set<String> reservedScopes = scopeService.toStrings(scopeService.getReserved());

    // Scopes linked to the refresh token, i.e. authorized by the user
    Set<String> authorizedScopes = Sets.newHashSet(
        refreshToken.getAuthenticationHolder().getAuthentication().getOAuth2Request().getScope());
    authorizedScopes.removeAll(reservedScopes);

    // Scopes requested in this refresh token flow
    Set<String> requestedScopes = Sets.newHashSet();
    if (authRequest.getScope() != null) {
      requestedScopes.addAll(authRequest.getScope());
    }

    requestedScopes.removeAll(reservedScopes);

    if (!requestedScopes.isEmpty()) {
      // Check for upscoping
      if (scopeService.scopesMatch(authorizedScopes, requestedScopes)) {
        token.setScope(requestedScopes);
      } else {
        String errorMsg = "Up-scoping is not allowed.";
        logger.error(errorMsg);
        throw new InvalidScopeException(errorMsg);
      }

    } else {
      // Preserve scopes linked to the original refresh token
      token.setScope(authorizedScopes);
    }

    token.setClient(client);

    if (client.getAccessTokenValiditySeconds() != null
        && client.getAccessTokenValiditySeconds() > 0) {
      Date expiration =
          new Date(System.currentTimeMillis() + (client.getAccessTokenValiditySeconds() * 1000L));
      token.setExpiration(expiration);
    }

    if (client.isReuseRefreshToken()) {
      // if the client re-uses refresh tokens, do that
      token.setRefreshToken(refreshToken);
    } else {
      // otherwise, make a new refresh token
      IamRefreshToken newRefresh = createRefreshToken(client, authHolder);
      token.setRefreshToken(newRefresh);

      // clean up the old refresh token
      tokenRepository.removeRefreshToken(refreshToken);
    }

    token.setAuthenticationHolder(authHolder);

    OAuth2Authentication authentication = authHolder.getAuthentication();

    tokenEnhancer.enhance(token, new OAuth2Authentication(
        authentication.getOAuth2Request().refresh(authRequest), authHolder.getUserAuth()));

    tokenRepository.saveAccessToken(token);

    return token;
  }

  @Override
  public OAuth2Authentication loadAuthentication(String accessTokenValue)
      throws AuthenticationException {

    IamAccessToken accessToken =
        clearExpiredAccessToken(accessTokenRepository.findByTokenValue(accessTokenValue));

    if (accessToken == null) {
      throw new InvalidTokenException("Invalid access token: " + accessTokenValue);
    } else {
      return accessToken.getAuthenticationHolder().getAuthentication();
    }
  }


  /**
   * Get an access token from its token value.
   */
  @Override
  public IamAccessToken readAccessToken(String accessTokenValue)
      throws AuthenticationException {
    IamAccessToken accessToken =
        clearExpiredAccessToken(tokenRepository.getAccessTokenByValue(accessTokenValue));
    if (accessToken == null) {
      throw new InvalidTokenException(
          "Access token for value " + accessTokenValue + " was not found");
    } else {
      return accessToken;
    }
  }

  /**
   * Get an access token by its authentication object.
   */
  @Override
  public IamAccessToken getAccessToken(OAuth2Authentication authentication) {
    // TODO: implement this against the new service (#825)
    throw new UnsupportedOperationException(
        "Unable to look up access token from authentication object.");
  }

  /**
   * Get a refresh token by its token value.
   */
  @Override
  public IamRefreshToken getRefreshToken(String refreshTokenValue)
      throws AuthenticationException {
    IamRefreshToken refreshToken =
        tokenRepository.getRefreshTokenByValue(refreshTokenValue);
    if (refreshToken == null) {
      throw new InvalidTokenException(
          "Refresh token for value " + refreshTokenValue + " was not found");
    } else {
      return refreshToken;
    }
  }

  /**
   * Revoke a refresh token and all access tokens issued to it.
   */
  @Override
  @Transactional(value = "defaultTransactionManager")
  public void revokeRefreshToken(IamRefreshToken refreshToken) {
    tokenRepository.clearAccessTokensForRefreshToken(refreshToken);
    tokenRepository.removeRefreshToken(refreshToken);
  }

  /**
   * Revoke an access token.
   */
  @Override
  @Transactional(value = "defaultTransactionManager")
  public void revokeAccessToken(IamAccessToken accessToken) {
    tokenRepository.removeAccessToken(accessToken);
  }

  @Override
  public List<IamAccessToken> getAccessTokensForClient(IamClient client) {
    return tokenRepository.getAccessTokensForClient(client);
  }

  @Override
  public List<IamRefreshToken> getRefreshTokensForClient(IamClient client) {
    return tokenRepository.getRefreshTokensForClient(client);
  }

  /**
   * Clears out expired tokens and any abandoned authentication objects
   */
  @Override
  public void clearExpiredTokens() {
    logger.debug("Cleaning out all expired tokens");

    new AbstractPageOperationTemplate<IamAccessToken>("clearExpiredAccessTokens") {
      @Override
      public Collection<IamAccessToken> fetchPage() {
        return tokenRepository.getAllExpiredAccessTokens(new DefaultPageCriteria());
      }

      @Override
      public void doOperation(IamAccessToken item) {
        revokeAccessToken(item);
      }
    }.execute();

    new AbstractPageOperationTemplate<IamRefreshToken>("clearExpiredRefreshTokens") {
      @Override
      public Collection<IamRefreshToken> fetchPage() {
        return tokenRepository.getAllExpiredRefreshTokens(new DefaultPageCriteria());
      }

      @Override
      public void doOperation(IamRefreshToken item) {
        revokeRefreshToken(item);
      }
    }.execute();

    new AbstractPageOperationTemplate<AuthenticationHolderEntity>(
        "clearExpiredAuthenticationHolders") {
      @Override
      public Collection<AuthenticationHolderEntity> fetchPage() {
        return authenticationHolderRepository
          .getOrphanedAuthenticationHolders(new DefaultPageCriteria());
      }

      @Override
      public void doOperation(AuthenticationHolderEntity item) {
        authenticationHolderRepository.remove(item);
      }
    }.execute();
  }

  /*
   * (non-Javadoc)
   * 
   * @see org.mitre.oauth2.service.OAuth2TokenEntityService#saveAccessToken(org.mitre.oauth2.model.
   * IamAccessToken)
   */
  @Override
  @Transactional(value = "defaultTransactionManager")
  public IamAccessToken saveAccessToken(IamAccessToken accessToken) {
    IamAccessToken newToken = tokenRepository.saveAccessToken(accessToken);

    // if the old token has any additional information for the return from the token endpoint, carry
    // it through here after save
    if (accessToken.getAdditionalInformation() != null
        && !accessToken.getAdditionalInformation().isEmpty()) {
      newToken.getAdditionalInformation().putAll(accessToken.getAdditionalInformation());
    }

    return newToken;
  }

  /*
   * (non-Javadoc)
   * 
   * @see org.mitre.oauth2.service.OAuth2TokenEntityService#saveRefreshToken(org.mitre.oauth2.model.
   * IamRefreshToken)
   */
  @Override
  @Transactional(value = "defaultTransactionManager")
  public IamRefreshToken saveRefreshToken(IamRefreshToken refreshToken) {
    return tokenRepository.saveRefreshToken(refreshToken);
  }

  /**
   * @return the tokenEnhancer
   */
  public TokenEnhancer getTokenEnhancer() {
    return tokenEnhancer;
  }

  /**
   * @param tokenEnhancer the tokenEnhancer to set
   */
  public void setTokenEnhancer(TokenEnhancer tokenEnhancer) {
    this.tokenEnhancer = tokenEnhancer;
  }

  @Override
  public IamAccessToken getRegistrationAccessTokenForClient(IamClient client) {
    List<IamAccessToken> allTokens = getAccessTokensForClient(client);

    for (IamAccessToken token : allTokens) {
      if ((token.getScope().contains(SystemScopeService.REGISTRATION_TOKEN_SCOPE)
          || token.getScope().contains(SystemScopeService.RESOURCE_TOKEN_SCOPE))
          && token.getScope().size() == 1) {
        // if it only has the registration scope, then it's a registration token
        return token;
      }
    }

    return null;
  }
  
 


  @Override
  public Set<IamRefreshToken> getAllRefreshTokensForUser(String id) {
    Set<IamRefreshToken> results = Sets.newLinkedHashSet();
    results.addAll(refreshTokenRepo.findValidRefreshTokensForUser(id, new Date()));
    return results;
  }

  @Override
  public void revokeAccessToken(IamAccessToken accessToken) {
    accessTokenRepo.delete(accessToken);
  }

  @Override
  public void revokeRefreshToken(IamRefreshToken refreshToken) {
    refreshTokenRepo.delete(refreshToken);
  }

  @SuppressWarnings("deprecation")
  public IamAccessToken createAccessToken(OAuth2Authentication authentication) {

    IamAccessToken token = super.createAccessToken(authentication);

    if (iamProperties.getClient().isTrackLastUsed()) {
      updateClientLastUsed(token);
    }

    eventPublisher.publishEvent(new AccessTokenIssuedEvent(this, token));
    return token;
  }

  @Override
  public IamRefreshToken createRefreshToken(IamClient client,
      AuthenticationHolderEntity authHolder) {

    IamRefreshToken token = super.createRefreshToken(client, authHolder);

    eventPublisher.publishEvent(new RefreshTokenIssuedEvent(this, token));
    return token;
  }

  @SuppressWarnings("deprecation")
  public IamAccessToken refreshAccessToken(String refreshTokenValue,
      TokenRequest authRequest) {

    IamAccessToken token = super.refreshAccessToken(refreshTokenValue, authRequest);

    if (iamProperties.getClient().isTrackLastUsed()) {
      updateClientLastUsed(token);
    }

    eventPublisher.publishEvent(new AccessTokenIssuedEvent(this, token));
    return token;
  }

  private void updateClientLastUsed(IamAccessToken token) {
    IamClient client = token.getClient();
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
}
