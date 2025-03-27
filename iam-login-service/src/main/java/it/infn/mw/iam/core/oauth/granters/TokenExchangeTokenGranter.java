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
import static java.lang.String.format;

import java.text.ParseException;
import java.util.Objects;
import java.util.Set;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.oauth2.service.OAuth2TokenEntityService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;

import it.infn.mw.iam.core.oauth.exchange.TokenExchangePdp;
import it.infn.mw.iam.core.oauth.exchange.TokenExchangePdpResult;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAuthority;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
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
  private final AUPSignatureCheckService signatureCheckService;
  private final TokenExchangePdp exchangePdp;
  private final IamAccountRepository accountRepository;


  public TokenExchangeTokenGranter(OAuth2TokenEntityService tokenServices,
      ClientDetailsEntityService clientDetailsService, OAuth2RequestFactory requestFactory,
      AUPSignatureCheckService signatureCheckService, TokenExchangePdp exchangePdp,
      IamAccountRepository accountRepository) {
    super(tokenServices, clientDetailsService, requestFactory, TOKEN_EXCHANGE_GRANT_TYPE);
    this.tokenServices = tokenServices;
    this.signatureCheckService = signatureCheckService;
    this.exchangePdp = exchangePdp;
    this.accountRepository = accountRepository;
  }

  protected void validateExchange(final ClientDetails actorClient, final TokenRequest tokenRequest,
      OAuth2AccessTokenEntity subjectToken) {

    ClientDetailsEntity subjectClient = subjectToken.getClient();
    Set<String> requestedScopes = tokenRequest.getScope();

    if (Objects.isNull(requestedScopes) || requestedScopes.isEmpty()) {
      LOG.debug(
          "No scope parameter found in token exchange request, defaulting to scopes linked to the suject token");
      requestedScopes = subjectToken.getScope();
    }

    if (subjectClient.equals(actorClient) && requestedScopes.contains(OFFLINE_ACCESS_SCOPE)) {
      throw new OAuth2AccessDeniedException(
          "Token exchange not allowed: the actor and the subject are the same client and offline_access is in the requested scopes");
    }

    TokenExchangePdpResult result =
        exchangePdp.validateTokenExchange(tokenRequest, subjectClient, actorClient);

    LOG.debug("Token exchange pdp decision: {}", result.decision());

    switch (result.decision()) {
      case PERMIT:
        return;
      case INVALID_SCOPE:
        if (result.message().isPresent() && result.invalidScope().isPresent()) {
          throw new InvalidScopeException(
              format("%s: %s", result.message().get(), result.invalidScope().get()));
        }
        throw new InvalidScopeException("An invalid scope was requested");
      default:
        if (result.message().isPresent()) {
          throw new OAuth2AccessDeniedException(result.message().get());
        }
        throw new OAuth2AccessDeniedException("Token exchange not allowed");
    }
  }

  @Override
  protected OAuth2Authentication getOAuth2Authentication(final ClientDetails actorClient,
      final TokenRequest tokenRequest) {

    if (tokenRequest.getRequestParameters().get("actor_token") != null
        || tokenRequest.getRequestParameters().get("want_composite") != null) {
      throw new InvalidRequestException("Delegation not supported");
    }

    String subjectTokenValue = tokenRequest.getRequestParameters().get("subject_token");
    OAuth2AccessTokenEntity subjectToken = tokenServices.readAccessToken(subjectTokenValue);

    String sub = null;
    try {
      sub = subjectToken.getJwt().getJWTClaimsSet().getStringClaim("sub");
    } catch (ParseException e) {
      throw new InvalidRequestException("Subject token has no sub claim");
    }

    Authentication userAuthentication = null;

    if (!sub.equals(subjectToken.getClient().getClientId())) {
      IamAccount account = accountRepository.findByUuid(sub)
        .orElseThrow(() -> new InvalidRequestException("Subject token sub is not a valid accoun"));
      if (signatureCheckService.needsAupSignature(account)) {
        throw new InvalidGrantException(
            format("User %s needs to sign AUP for this organization in order to proceed.",
                account.getUsername()));
      }
      userAuthentication = new UsernamePasswordAuthenticationToken(account.getUsername(), null,
          AuthorityUtils.createAuthorityList(account.getAuthorities().stream()
              .map(IamAuthority::getAuthority)
              .toArray(String[]::new)));
    }

    OAuth2Authentication authentication = new OAuth2Authentication(
        getRequestFactory().createOAuth2Request(actorClient, tokenRequest), userAuthentication);

    validateExchange(actorClient, tokenRequest, subjectToken);

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

}
