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
package it.infn.mw.iam.core.oauth.granters;

import static it.infn.mw.iam.core.oauth.exchange.TokenExchangePdpResult.Decision.INVALID_SCOPE;
import static it.infn.mw.iam.core.oauth.exchange.TokenExchangePdpResult.Decision.PERMIT;
import static java.lang.String.format;

import java.util.Set;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.oauth2.service.OAuth2TokenEntityService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.ParsedAccessToken;
import it.infn.mw.iam.core.TokenUtils;
import it.infn.mw.iam.core.oauth.exchange.TokenExchangePdp;
import it.infn.mw.iam.core.oauth.exchange.TokenExchangePdpResult;
import it.infn.mw.iam.service.aup.AUPSignatureCheckService;

@SuppressWarnings("deprecation")
public class TokenExchangeTokenGranter extends AbstractTokenGranter {

  public static final Logger LOG = LoggerFactory.getLogger(TokenExchangeTokenGranter.class);

  public static final String TOKEN_EXCHANGE_GRANT_TYPE =
      "urn:ietf:params:oauth:grant-type:token-exchange";

  private static final String TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";

  private static final String AUDIENCE_FIELD = "audience";
  private static final String OFFLINE_ACCESS_SCOPE = "offline_access";

  private final OAuth2TokenEntityService tokenService;
  private final ClientDetailsEntityService clientDetailsService;
  private final IamProperties iamProperties;
  private final AccountUtils accountUtils;
  private final AUPSignatureCheckService signatureCheckService;
  private final TokenExchangePdp exchangePdp;
  private final TokenUtils tokenUtils;

  public TokenExchangeTokenGranter(OAuth2TokenEntityService tokenService,
      ClientDetailsEntityService clientDetailsService, OAuth2RequestFactory requestFactory,
      IamProperties iamProperties, TokenUtils tokenUtils, AccountUtils accountUtils,
      AUPSignatureCheckService signatureCheckService, TokenExchangePdp exchangePdp) {

    super(tokenService, clientDetailsService, requestFactory, TOKEN_EXCHANGE_GRANT_TYPE);

    this.tokenService = tokenService;
    this.clientDetailsService = clientDetailsService;
    this.iamProperties = iamProperties;
    this.tokenUtils = tokenUtils;
    this.accountUtils = accountUtils;
    this.signatureCheckService = signatureCheckService;
    this.exchangePdp = exchangePdp;
  }

  @Override
  protected OAuth2Authentication getOAuth2Authentication(ClientDetails actorClient,
      TokenRequest tokenRequest) {

    rejectDelegationIfPresent(tokenRequest);

    ClientDetailsEntity actor = castClient(actorClient);

    SubjectTokenContext subjectContext = null;
    try {
      subjectContext = resolveSubjectToken(actor, tokenRequest);
    } catch (InvalidTokenException e) {
      throw new InvalidGrantException(e.getMessage(), e);
    }

    OAuth2Authentication finalAuth =
        rebuildAuthentication(actorClient, tokenRequest, subjectContext.authentication());

    enrichAudience(tokenRequest, finalAuth);

    return finalAuth;
  }

  @Override
  protected OAuth2AccessToken getAccessToken(ClientDetails client, TokenRequest tokenRequest) {

    OAuth2Authentication auth = getOAuth2Authentication(client, tokenRequest);

    OAuth2AccessToken token = tokenService.createAccessToken(auth);

    token.getAdditionalInformation().put("issued_token_type", TOKEN_TYPE);

    return token;
  }

  private SubjectTokenContext resolveSubjectToken(ClientDetailsEntity actor, TokenRequest request) {

    String tokenValue = request.getRequestParameters().get("subject_token");

    if (iamProperties.getAccessToken().isStoreOnDatabase()) {
      return resolveFromDatabase(actor, request, tokenValue);
    }

    return resolveFromJwt(actor, request, tokenValue);
  }

  private SubjectTokenContext resolveFromDatabase(ClientDetailsEntity actor, TokenRequest request,
      String tokenValue) {

    OAuth2AccessTokenEntity token = tokenUtils.loadFromDatabase(tokenValue)
      .orElseThrow(() -> new InvalidTokenException("Invalid subject token: not found on database"));

    OAuth2Authentication authentication = token.getAuthenticationHolder().getAuthentication();

    validateExchange(actor, request, authentication, token.getScope(),
        token.getClient().getClientId());

    return new SubjectTokenContext(authentication, token.getScope(),
        token.getClient().getClientId());
  }

  private SubjectTokenContext resolveFromJwt(ClientDetailsEntity actor, TokenRequest request,
      String tokenValue) {

    ParsedAccessToken parsed = tokenUtils.parseAccessToken(tokenValue);

    OAuth2Authentication authentication = tokenUtils.getAuthentication(parsed);

    try {
      tokenUtils.validate(parsed);
    } catch (InvalidTokenException e) {
      throw new InvalidGrantException(e.getMessage(), e);
    }

    validateExchange(actor, request, authentication, parsed.scopes(), parsed.clientId());

    return new SubjectTokenContext(authentication, parsed.scopes(), parsed.clientId());
  }

  private void validateExchange(ClientDetailsEntity actorClient, TokenRequest tokenRequest,
      OAuth2Authentication authentication, Set<String> subjectScopes, String subjectClientId) {

    Set<String> requestedScopes = resolveScopes(tokenRequest, subjectScopes);

    validateAupIfNeeded(authentication);

    logRequest(actorClient, authentication, subjectClientId, tokenRequest, requestedScopes);

    validateOfflineAccess(actorClient, subjectClientId, requestedScopes);

    validateWithPdp(actorClient, tokenRequest, subjectClientId);
  }

  private Set<String> resolveScopes(TokenRequest request, Set<String> subjectScopes) {

    Set<String> scopes = request.getScope();

    if (scopes == null || scopes.isEmpty()) {
      LOG.debug("Defaulting to subject token scopes");
      return subjectScopes;
    }

    return scopes;
  }

  private void validateAupIfNeeded(OAuth2Authentication authentication) {

    if (authentication.getUserAuthentication() == null) {
      return;
    }

    accountUtils.getAuthenticatedUserAccount(authentication.getUserAuthentication())
      .filter(signatureCheckService::needsAupSignature)
      .ifPresent(account -> {
        throw new InvalidGrantException(
            format("User with uuid %s needs to sign AUP for this organization in order to proceed.",
                account.getUuid()));
      });
  }

  private void validateOfflineAccess(ClientDetailsEntity actor, String subjectClientId,
      Set<String> scopes) {

    if (actor.getClientId().equals(subjectClientId) && scopes.contains(OFFLINE_ACCESS_SCOPE)) {
      throw new OAuth2AccessDeniedException(
          "Token exchange not allowed: same client and offline_access requested");
    }
  }

  private void validateWithPdp(ClientDetailsEntity actor, TokenRequest request,
      String subjectClientId) {

    ClientDetailsEntity subject = clientDetailsService.loadClientByClientId(subjectClientId);

    TokenExchangePdpResult result = exchangePdp.validateTokenExchange(request, subject, actor);

    handlePdpDecision(result);
  }

  private void handlePdpDecision(TokenExchangePdpResult result) {

    LOG.debug("Token exchange pdp decision: {}", result.decision());

    if (INVALID_SCOPE.equals(result.decision())) {
      throw new InvalidScopeException(result.message()
        .flatMap(m -> result.invalidScope().map(s -> format("%s: %s", m, s)))
        .orElse("An invalid scope was requested"));
    }

    if (!PERMIT.equals(result.decision())) {
      throw new OAuth2AccessDeniedException(result.message().orElse("Token exchange not allowed"));
    }
  }

  private void rejectDelegationIfPresent(TokenRequest request) {

    if (request.getRequestParameters().get("actor_token") != null
        || request.getRequestParameters().get("want_composite") != null) {
      throw new InvalidRequestException("Delegation not supported");
    }
  }

  private ClientDetailsEntity castClient(ClientDetails client) {

    if (client instanceof ClientDetailsEntity entity) {
      return entity;
    }

    throw new IllegalStateException("Invalid client entity");
  }

  private OAuth2Authentication rebuildAuthentication(ClientDetails actorClient,
      TokenRequest request, OAuth2Authentication subjectAuth) {

    return new OAuth2Authentication(getRequestFactory().createOAuth2Request(actorClient, request),
        subjectAuth.getUserAuthentication());
  }

  private void enrichAudience(TokenRequest request, OAuth2Authentication auth) {

    String audience = request.getRequestParameters().get(AUDIENCE_FIELD);

    if (audience != null && !audience.isBlank()) {
      auth.getOAuth2Request().getExtensions().put("aud", audience);
    }
  }

  private void logRequest(ClientDetailsEntity actor, OAuth2Authentication authentication,
      String subjectClientId, TokenRequest request, Set<String> scopes) {

    String audience = request.getRequestParameters().get(AUDIENCE_FIELD);

    if (authentication.getUserAuthentication() == null) {
      LOG.info("Client '{}' exchanges token from '{}' audience '{}' scopes '{}'",
          actor.getClientId(), subjectClientId, audience, scopes);
      return;
    }

    LOG.info("Client '{}' impersonates '{}' from '{}' audience '{}' scopes '{}'",
        actor.getClientId(), authentication.getUserAuthentication().getName(), subjectClientId,
        audience, scopes);
  }

  private record SubjectTokenContext(OAuth2Authentication authentication, Set<String> scopes,
      String clientId) {
  }

}
