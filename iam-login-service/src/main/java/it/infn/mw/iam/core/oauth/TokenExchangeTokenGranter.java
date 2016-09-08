package it.infn.mw.iam.core.oauth;

import java.util.Arrays;
import java.util.List;
import java.util.Set;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.oauth2.service.OAuth2TokenEntityService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;

import com.google.common.base.Strings;
import com.google.common.collect.Sets;

public class TokenExchangeTokenGranter extends AbstractTokenGranter {

  public static final Logger LOG = LoggerFactory.getLogger(TokenExchangeTokenGranter.class);

  private static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";
  private static final String TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";

  /**
   * These scopes, in order to be "exchanged" across services, need to be present in the set of
   * scopes linked to the subject token that is presented for the exchange.
   */
  private static final List<String> CHAINED_SCOPES = Arrays.asList("openid", "profile", "email",
      "address", "phone", "offline_access", "scim:read", "scim:write");

  // keep down-cast versions so we can get to the right queries
  private OAuth2TokenEntityService tokenServices;
  private ClientDetailsEntityService clientDetailsService;

  @Autowired
  public TokenExchangeTokenGranter(final OAuth2TokenEntityService tokenServices,
      final ClientDetailsEntityService clientDetailsService,
      final OAuth2RequestFactory requestFactory) {
    super(tokenServices, clientDetailsService, requestFactory, GRANT_TYPE);
    this.tokenServices = tokenServices;
    this.clientDetailsService = clientDetailsService;
  }

  @Override
  protected OAuth2Authentication getOAuth2Authentication(final ClientDetails client,
      final TokenRequest tokenRequest) throws AuthenticationException, InvalidTokenException {

    if (tokenRequest.getRequestParameters().get("actor_token") != null
        || tokenRequest.getRequestParameters().get("want_composite") != null) {
      throw new InvalidRequestException("Delegation not yet supported in Token Exchange");
    }

    // read and load up the existing token
    String incomingTokenValue = tokenRequest.getRequestParameters().get("subject_token");

    OAuth2AccessTokenEntity incomingToken = tokenServices.readAccessToken(incomingTokenValue);

    // read audience: must contain a valid client_id
    String incomingAudience = tokenRequest.getRequestParameters().get("audience");

    if (Strings.isNullOrEmpty(incomingAudience)) {
      throw new InvalidRequestException("Missing audience field in Token Exchange");
    }

    ClientDetailsEntity targetClient = clientDetailsService.loadClientByClientId(incomingAudience);

    // check for scoping in the request, can't up-scope with a chained request
    Set<String> requestedScopes = tokenRequest.getScope();
    Set<String> targetClientScopes = targetClient.getScope();
    Set<String> incomingTokenScopes = incomingToken.getScope();

    // if our scopes are a valid subset of what's allowed, we can continue
    if (targetClientScopes.containsAll(requestedScopes)) {

      LOG.info("Client with id [{}] requests token exchange for audience [{}] with scopes {}",
          client.getClientId(), incomingAudience, requestedScopes);

      // check chained scopes
      for (String scope : CHAINED_SCOPES) {
        if (requestedScopes.contains(scope) && !incomingTokenScopes.contains(scope)) {
          throw new InvalidScopeException(
              String.format("Subject Token MUST contain requested scope [%s]", scope));
        }
      }

      tokenRequest.setScope(Sets.intersection(requestedScopes, targetClientScopes));

      // NOTE: don't revoke the existing access token

      // create a new access token
      OAuth2Authentication authentication =
          new OAuth2Authentication(getRequestFactory().createOAuth2Request(client, tokenRequest),
              incomingToken.getAuthenticationHolder().getAuthentication().getUserAuthentication());
      authentication.getOAuth2Request().getExtensions();

      return authentication;

    } else {
      throw new InvalidScopeException("Invalid scope in Token Exchange request", requestedScopes);
    }

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
