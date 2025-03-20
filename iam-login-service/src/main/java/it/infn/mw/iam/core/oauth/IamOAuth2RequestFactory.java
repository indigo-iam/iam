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

import static com.google.common.base.Strings.isNullOrEmpty;
import static it.infn.mw.iam.core.oauth.granters.TokenExchangeTokenGranter.TOKEN_EXCHANGE_GRANT_TYPE;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.mitre.oauth2.model.AuthorizationCodeEntity;
import org.mitre.oauth2.model.DeviceCode;
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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Joiner;

import it.infn.mw.iam.core.error.InvalidResourceError;
import it.infn.mw.iam.authn.multi_factor_authentication.IamAuthenticationMethodReference;
import it.infn.mw.iam.authn.oidc.OidcExternalAuthenticationToken;
import it.infn.mw.iam.core.ExtendedAuthenticationToken;
import it.infn.mw.iam.core.oauth.profile.JWTProfileResolver;
import it.infn.mw.iam.core.oauth.scope.pdp.ScopeFilter;

@SuppressWarnings("deprecation")
public class IamOAuth2RequestFactory extends ConnectOAuth2RequestFactory {

  public static final Logger LOG = LoggerFactory.getLogger(IamOAuth2RequestFactory.class);

  public static final String RESOURCE = "resource";
  protected static final List<String> AUD_KEYS = Arrays.asList(RESOURCE, "aud", "audience");
  public static final String AUD_KEY = "aud";

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

    validateAndUpdateAudienceRequest(inputParams);

    AuthorizationRequest authzRequest = super.createAuthorizationRequest(inputParams);

    Set<IamAuthenticationMethodReference> amrSet;
    if (authn instanceof ExtendedAuthenticationToken extendedToken) {
      amrSet = extendedToken.getAuthenticationMethodReferences();
      processToken(amrSet, authzRequest);
    } else if (authn instanceof OidcExternalAuthenticationToken oidcToken) {
      amrSet = oidcToken.getAuthenticationMethodReferences();
      processToken(amrSet, authzRequest);
    }

    return authzRequest;
  }

  private void processToken(Set<IamAuthenticationMethodReference> amrSet,
      AuthorizationRequest authzRequest) {
    try {
      authzRequest.getExtensions().put("amr", parseAuthenticationMethodReferences(amrSet));
    } catch (JsonProcessingException e) {
      LOG.error("Failed to convert amr set to JSON array", e);
    }
  }

  private String parseAuthenticationMethodReferences(Set<IamAuthenticationMethodReference> amrSet)
      throws JsonProcessingException {
    List<String> amrList = new ArrayList<>();
    for (IamAuthenticationMethodReference amr : amrSet) {
      amrList.add(amr.getName());
    }

    ObjectMapper objectMapper = new ObjectMapper();
    return objectMapper.writeValueAsString(amrList);
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

    return new TokenRequest(updatedTokenRequestParameters(requestParameters, authenticatedClient),
        clientId, scopeFilter.filterScopes(scopes, authn), grantType);
  }

  private Map<String, String> updatedTokenRequestParameters(
      Map<String, String> tokenRequestParameters, ClientDetails client) {

    String grantType = tokenRequestParameters.get(OAuth2Utils.GRANT_TYPE);
    Optional<Map<String, String>> authzRequestParams = java.util.Optional.empty();

    switch (grantType) {

      case AUTHZ_CODE_GRANT:
        authzRequestParams = Optional
          .ofNullable(authzCodeRepository.getByCode(tokenRequestParameters.get(AUTHZ_CODE_KEY)))
          .map(AuthorizationCodeEntity::getAuthenticationHolder)
          .map(holder -> holder.getRequestParameters());
        break;

      case DEVICE_CODE_GRANT:
        authzRequestParams = Optional
          .ofNullable(
              deviceCodeService.findDeviceCode(tokenRequestParameters.get(DEVICE_CODE_KEY), client))
          .map(DeviceCode::getAuthenticationHolder)
          .map(holder -> holder.getRequestParameters());
        break;

      case REFRESH_TOKEN_GRANT:
        authzRequestParams = Optional
          .ofNullable(tokenServices.getRefreshToken(tokenRequestParameters.get(REFRESH_TOKEN_KEY)))
          .map(token -> token.getAuthenticationHolder())
          .map(holder -> holder.getRequestParameters());
        break;

      default:
        break;
    }

    validateAndUpdateAudienceRequest(tokenRequestParameters);

    authzRequestParams.ifPresent(arp -> {

      boolean hasTokenAudKey = tokenRequestParameters.containsKey(AUD_KEY);
      boolean hasAuthzResourceParam = arp.containsKey(RESOURCE);
      boolean hasTokenResourceParam = tokenRequestParameters.containsKey(RESOURCE);

      if (hasTokenAudKey) {
        if (hasAuthzResourceParam || hasTokenResourceParam) {
          List<String> tokenResourceParams = splitBySpace(tokenRequestParameters.get(AUD_KEY));
          tokenRequestParameters.put(AUD_KEY, getAllowedResource(tokenResourceParams, arp));
        }
      } else if (hasAuthzResourceParam) {
        tokenRequestParameters.put(AUD_KEY, arp.get(RESOURCE));
        // Required by RT flow after device
        tokenRequestParameters.put(RESOURCE, arp.get(RESOURCE));
      }

    });

    return tokenRequestParameters;

  }

  private void validateAndUpdateAudienceRequest(Map<String, String> params) {

    if (params.containsKey(RESOURCE)) {
      List<String> resourceParams = splitBySpace(params.get(RESOURCE));
      resourceParams.forEach(aud -> validateUrl(aud));
    }

    Optional<String> audience = Optional.ofNullable(getFirstNotEmptyAudience(params));
    audience.ifPresent(aud -> params.put(AUD_KEY, aud));
  }

  private String getFirstNotEmptyAudience(Map<String, String> params) {
    return AUD_KEYS.stream()
      .map(params::get)
      .filter(aud -> !isNullOrEmpty(aud))
      .findFirst()
      .orElse(null);
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
