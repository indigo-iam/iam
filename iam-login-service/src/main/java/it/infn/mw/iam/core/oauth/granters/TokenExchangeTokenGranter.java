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

import static com.google.common.base.Strings.isNullOrEmpty;
import static it.infn.mw.iam.core.oauth.exchange.TokenExchangePdpResult.Decision.INVALID_SCOPE;
import static it.infn.mw.iam.core.oauth.exchange.TokenExchangePdpResult.Decision.PERMIT;
import static java.lang.String.format;
import static java.util.Objects.isNull;

import java.util.Objects;
import java.util.Optional;
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
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.service.aup.AUPSignatureCheckService;

@SuppressWarnings("deprecation")
public class TokenExchangeTokenGranter extends AbstractTokenGranter {

  public static final Logger LOG = LoggerFactory.getLogger(TokenExchangeTokenGranter.class);

  public static final String TOKEN_EXCHANGE_GRANT_TYPE =
      "urn:ietf:params:oauth:grant-type:token-exchange";
  private static final String TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";
  private static final String AUDIENCE_FIELD = "audience";
  private static final String OFFLINE_ACCESS_SCOPE = "offline_access";

  private final OAuth2TokenEntityService tokenServices;

  private IamProperties iamProperties;
  private AccountUtils accountUtils;
  private AUPSignatureCheckService signatureCheckService;
  private TokenExchangePdp exchangePdp;
  private ClientDetailsEntityService clientDetailsService;
  private TokenUtils tokenUtils;

  public TokenExchangeTokenGranter(final OAuth2TokenEntityService tokenServices,
      final ClientDetailsEntityService clientDetailsService,
      final OAuth2RequestFactory requestFactory, IamProperties iamProperties,
      TokenUtils tokenUtils) {
    super(tokenServices, clientDetailsService, requestFactory, TOKEN_EXCHANGE_GRANT_TYPE);
    this.iamProperties = iamProperties;
    this.clientDetailsService = clientDetailsService;
    this.tokenServices = tokenServices;
    this.tokenUtils = tokenUtils;
  }

  private void validateExchange(ClientDetailsEntity actorClient, TokenRequest tokenRequest,
      OAuth2Authentication authentication, Set<String> subjectTokenScopes,
      String subjectTokenClientId) {

    String audience = tokenRequest.getRequestParameters().get(AUDIENCE_FIELD);
    Set<String> requestedScopes = tokenRequest.getScope();

    if (Objects.isNull(requestedScopes) || requestedScopes.isEmpty()) {
      LOG.debug(
          "No scope parameter found in token exchange request, defaulting to scopes linked to the suject token");
      requestedScopes = subjectTokenScopes;
    }

    if (!isNull(authentication.getUserAuthentication())) {

      Optional<IamAccount> account =
          accountUtils.getAuthenticatedUserAccount(authentication.getUserAuthentication());

      if (account.isPresent() && signatureCheckService.needsAupSignature(account.get())) {
        throw new InvalidGrantException(
            format("User %s needs to sign AUP for this organization in order to proceed.",
                account.get().getUsername()));
      }

      LOG.info(
          "Client '{}' requests token exchange from client '{}' to impersonate user '{}' on audience '{}' with scopes '{}'",
          actorClient.getClientId(), subjectTokenClientId,
          authentication.getUserAuthentication().getName(), audience, requestedScopes);

    } else {

      LOG.info(
          "Client '{}' requests token exchange from client '{}' on audience '{}' with scopes '{}'",
          actorClient.getClientId(), subjectTokenClientId, audience, requestedScopes);
    }

    if (subjectTokenClientId.equals(actorClient.getClientId())
        && requestedScopes.contains(OFFLINE_ACCESS_SCOPE)) {
      throw new OAuth2AccessDeniedException(
          "Token exchange not allowed: the actor and the subject are the same client and offline_access is in the requested scopes");
    }

    ClientDetailsEntity subjectClient =
        clientDetailsService.loadClientByClientId(subjectTokenClientId);
    TokenExchangePdpResult result =
        exchangePdp.validateTokenExchange(tokenRequest, subjectClient, actorClient);

    LOG.debug("Token exchange pdp decision: {}", result.decision());


    if (INVALID_SCOPE.equals(result.decision())) {
      String errorMsg = "An invalid scope was requested";

      // These clauses will _always_ be true, but this way sonarcloud
      // does not complain...
      if (result.message().isPresent() && result.invalidScope().isPresent()) {
        errorMsg = format("%s: %s", result.message().get(), result.invalidScope().get());
      }

      throw new InvalidScopeException(errorMsg);

    } else if (!PERMIT.equals(result.decision())) {
      if (result.message().isPresent()) {
        throw new OAuth2AccessDeniedException(result.message().get());
      } else {
        throw new OAuth2AccessDeniedException("Token exchange not allowed");
      }
    }
  }

  protected void validateExchange(ClientDetailsEntity actorClient, TokenRequest tokenRequest,
      OAuth2AccessTokenEntity accessToken) {

    validateExchange(actorClient, tokenRequest,
        accessToken.getAuthenticationHolder().getAuthentication(), accessToken.getScope(),
        accessToken.getClient().getClientId());
  }

  protected void validateExchange(ClientDetailsEntity actorClient, TokenRequest tokenRequest,
      OAuth2Authentication authentication, ParsedAccessToken subjectToken) {

    validateExchange(actorClient, tokenRequest, authentication, subjectToken.scopes(),
        subjectToken.clientId());
  }

  @Override
  protected OAuth2Authentication getOAuth2Authentication(final ClientDetails actorClient,
      final TokenRequest tokenRequest) {

    if (tokenRequest.getRequestParameters().get("actor_token") != null
        || tokenRequest.getRequestParameters().get("want_composite") != null) {
      throw new InvalidRequestException("Delegation not supported");
    }

    if (!(actorClient instanceof ClientDetailsEntity actorClientEntity)) {
      throw new IllegalStateException("Invalid client entity");
    }

    String subjectTokenValue = tokenRequest.getRequestParameters().get("subject_token");

    OAuth2Authentication authentication;

    if (iamProperties.getAccessToken().isStoreOnDatabase()) {

      Optional<OAuth2AccessTokenEntity> accessTokenOnDb =
          tokenUtils.loadFromDatabase(subjectTokenValue);
      if (accessTokenOnDb.isEmpty()) {
        throw new InvalidTokenException("Invalid subject token: not found on database");
      }
      validateExchange(actorClientEntity, tokenRequest, accessTokenOnDb.get());
      authentication = accessTokenOnDb.get().getAuthenticationHolder().getAuthentication();

    } else {

      ParsedAccessToken subjectToken = tokenUtils.parseAccessToken(subjectTokenValue);
      authentication = tokenUtils.getAuthentication(subjectToken);
      validateExchange(actorClientEntity, tokenRequest, authentication, subjectToken);
      tokenUtils.validate(subjectToken);
    }

    authentication =
        new OAuth2Authentication(getRequestFactory().createOAuth2Request(actorClient, tokenRequest),
            authentication.getUserAuthentication());

    String audience = tokenRequest.getRequestParameters().get(AUDIENCE_FIELD);
    if (!isNullOrEmpty(audience)) {
      authentication.getOAuth2Request().getExtensions().put("aud", audience);
    }

    return authentication;
  }

  @Override
  protected OAuth2AccessToken getAccessToken(final ClientDetails client,
      final TokenRequest tokenRequest) {

    OAuth2Authentication auth = getOAuth2Authentication(client, tokenRequest);
    OAuth2AccessToken accessToken = tokenServices.createAccessToken(auth);
    accessToken.getAdditionalInformation().put("issued_token_type", TOKEN_TYPE);

    return accessToken;
  }

  public void setAccountUtils(AccountUtils accountUtils) {
    this.accountUtils = accountUtils;
  }

  public void setSignatureCheckService(AUPSignatureCheckService signatureCheckService) {
    this.signatureCheckService = signatureCheckService;
  }

  public void setExchangePdp(TokenExchangePdp exchangePdp) {
    this.exchangePdp = exchangePdp;
  }

}
