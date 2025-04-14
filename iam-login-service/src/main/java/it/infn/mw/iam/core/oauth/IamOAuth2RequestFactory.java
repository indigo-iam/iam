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
package it.infn.mw.iam.core.oauth;

import static it.infn.mw.iam.core.oauth.granters.TokenExchangeTokenGranter.TOKEN_EXCHANGE_GRANT_TYPE;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.mitre.oauth2.repository.AuthorizationCodeRepository;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.oauth2.service.DeviceCodeService;
import org.mitre.oauth2.service.OAuth2TokenEntityService;
import org.mitre.openid.connect.request.ConnectOAuth2RequestFactory;
import org.mitre.openid.connect.web.AuthenticationTimeStamper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.TokenRequest;

import com.google.common.base.Joiner;

import it.infn.mw.iam.core.error.InvalidResourceError;
import it.infn.mw.iam.core.oauth.profile.JWTProfileResolver;
import it.infn.mw.iam.core.oauth.scope.pdp.ScopeFilter;

@SuppressWarnings("deprecation")
public class IamOAuth2RequestFactory extends ConnectOAuth2RequestFactory {

  public static final Logger LOG = LoggerFactory.getLogger(IamOAuth2RequestFactory.class);

  public static final String RESOURCE = "resource";

  public static final String PASSWORD_GRANT = "password";
  public static final String AUTHZ_CODE_GRANT = "authorization_code";
  public static final String DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";
  public static final String REFRESH_TOKEN_GRANT = "refresh_token";

  public static final String AUTHZ_CODE_KEY = "code";
  public static final String DEVICE_CODE_KEY = "device_code";
  public static final String REFRESH_TOKEN_KEY = "refresh_token";

  private final ScopeFilter scopeFilter;

  private final JWTProfileResolver profileResolver;

  private final Joiner joiner = Joiner.on(' ');
  private final ClientDetailsEntityService clientDetailsService;
  private final DeviceCodeService deviceCodeService;
  private final AuthorizationCodeRepository authzCodeRepository;
  private final OAuth2TokenEntityService tokenServices;

  public IamOAuth2RequestFactory(ClientDetailsEntityService clientDetailsService,
      ScopeFilter scopeFilter, JWTProfileResolver profileResolver,
      DeviceCodeService deviceCodeService, AuthorizationCodeRepository authzCodeRepository,
      OAuth2TokenEntityService tokenServices) {
    super(clientDetailsService);
    this.clientDetailsService = clientDetailsService;
    this.scopeFilter = scopeFilter;
    this.profileResolver = profileResolver;
    this.deviceCodeService = deviceCodeService;
    this.authzCodeRepository = authzCodeRepository;
    this.tokenServices = tokenServices;
  }

  @Override
  public AuthorizationRequest createAuthorizationRequest(Map<String, String> inputParams) {

    Authentication authn = SecurityContextHolder.getContext().getAuthentication();

    if (authn != null && !(authn instanceof AnonymousAuthenticationToken)) {
      Set<String> requestedScopes =
          OAuth2Utils.parseParameterList(inputParams.get(OAuth2Utils.SCOPE));

      inputParams.put(OAuth2Utils.SCOPE,
          joiner.join(scopeFilter.filterScopes(requestedScopes, authn)));
    }

    AuthorizationRequest authzRequest = super.createAuthorizationRequest(inputParams);

    if (inputParams.containsKey(RESOURCE)) {
      splitBySpace(inputParams.get(RESOURCE)).forEach(aud -> validateUrl(aud));
    }

    return authzRequest;

  }

  private void handlePasswordGrantAuthenticationTimestamp(OAuth2Request request) {
    if (PASSWORD_GRANT.equals(request.getGrantType())) {
      String now = Long.toString(System.currentTimeMillis());
      request.getExtensions().put(AuthenticationTimeStamper.AUTH_TIMESTAMP, now);
    }
  }


  @Override
  public OAuth2Request createOAuth2Request(ClientDetails client, TokenRequest tokenRequest) {

    OAuth2Request request = super.createOAuth2Request(client, tokenRequest);

    handlePasswordGrantAuthenticationTimestamp(request);

    profileResolver.resolveProfile(client.getClientId())
      .getRequestValidator()
      .validateRequest(request);

    return request;
  }


  @Override
  public TokenRequest createTokenRequest(Map<String, String> requestParameters,
      ClientDetails authenticatedClient) {

    Authentication authn = SecurityContextHolder.getContext().getAuthentication();

    String clientId = requestParameters.get(OAuth2Utils.CLIENT_ID);
    if (clientId == null) {
      clientId = authenticatedClient.getClientId();
    } else {
      if (!clientId.equals(authenticatedClient.getClientId())) {
        throw new InvalidClientException("Given client ID does not match authenticated client");
      }
    }

    String grantType = requestParameters.get(OAuth2Utils.GRANT_TYPE);

    Set<String> scopes = OAuth2Utils.parseParameterList(requestParameters.get(OAuth2Utils.SCOPE));

    if (scopes == null || scopes.isEmpty()) {
      if (TOKEN_EXCHANGE_GRANT_TYPE.equals(grantType)) {
        throw new InvalidRequestException(
            "The scope parameter is required for a token exchange request!");
      } else {
        ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
        scopes = clientDetails.getScope();
      }
    }

    if (requestParameters.containsKey(RESOURCE)) {
      return new TokenRequest(updateTokenRequestParameters(requestParameters, authenticatedClient),
          clientId, scopeFilter.filterScopes(scopes, authn), grantType);
    }

    return new TokenRequest(requestParameters, clientId, scopeFilter.filterScopes(scopes, authn),
        grantType);
  }

  private Map<String, String> updateTokenRequestParameters(
      Map<String, String> tokenRequestParameters, ClientDetails client) {

    List<String> tokenResourceParams = splitBySpace(tokenRequestParameters.get(RESOURCE));
    tokenResourceParams.forEach(aud -> validateUrl(aud));

    String grantType = tokenRequestParameters.get(OAuth2Utils.GRANT_TYPE);
    Map<String, String> authzRequestParams = null;

    switch (grantType) {
      case AUTHZ_CODE_GRANT:
        authzRequestParams =
            authzCodeRepository.getByCode(tokenRequestParameters.get(AUTHZ_CODE_KEY))
              .getAuthenticationHolder()
              .getRequestParameters();
        break;

      case DEVICE_CODE_GRANT:
        authzRequestParams =
            deviceCodeService.findDeviceCode(tokenRequestParameters.get(DEVICE_CODE_KEY), client)
              .getAuthenticationHolder()
              .getRequestParameters();
        break;

      case REFRESH_TOKEN_GRANT:
        authzRequestParams =
            tokenServices.getRefreshToken(tokenRequestParameters.get(REFRESH_TOKEN_KEY))
              .getAuthenticationHolder()
              .getRequestParameters();
        break;

      default:
        return tokenRequestParameters;
    }

    tokenRequestParameters.replace(RESOURCE,
        getAllowedResource(tokenResourceParams, authzRequestParams));

    return tokenRequestParameters;

  }

  private String getAllowedResource(List<String> tokenResourceParams,
      Map<String, String> authzRequestParams) {

    List<String> authzResourceParams = splitBySpace(authzRequestParams.get(RESOURCE));
    tokenResourceParams.retainAll(authzResourceParams);

    String allowedResource = String.join(" ", tokenResourceParams);
    if (allowedResource.isEmpty()) {
      throw new InvalidResourceError("The requested resource was not originally granted");
    }

    return allowedResource;
  }

  // Validation has been inspired by https://www.baeldung.com/java-validate-url
  public static void validateUrl(String url) {
    try {
      URI validURI = new URL(url).toURI();

      if (validURI.getRawQuery() != null) {
        throw new InvalidResourceError("The resource indicator contains a query component: " + url);
      }
      if (validURI.getRawFragment() != null) {
        throw new InvalidResourceError(
            "The resource indicator contains a fragment component: " + url);
      }

    } catch (MalformedURLException | URISyntaxException e) {
      throw new InvalidResourceError("Not a valid URI: " + url);
    }
  }

  public static List<String> splitBySpace(String str) {

    if (str == null) {
      return new ArrayList<>();
    }
    return Pattern.compile(" ").splitAsStream(str).collect(Collectors.toList());
  }

}
