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

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;

import it.infn.mw.iam.audit.events.utils.EventUtils;
import it.infn.mw.iam.core.jwk.ClientKeyCacheService;
import it.infn.mw.iam.core.oauth.device.DeviceCodeService;
import it.infn.mw.iam.core.oauth.profile.JWTProfileResolver;
import it.infn.mw.iam.core.oauth.scope.pdp.ScopeFilter;
import it.infn.mw.iam.core.oidc.AuthenticationTimeStamper;
import it.infn.mw.iam.persistence.model.AuthorizationCodeEntity;
import it.infn.mw.iam.persistence.model.DeviceCode;
import it.infn.mw.iam.persistence.repository.IamAuthorizationCodeRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;

@SuppressWarnings("deprecation")
public class IamOAuth2RequestFactory extends DefaultOAuth2RequestFactory {

  public static final Logger LOG = LoggerFactory.getLogger(IamOAuth2RequestFactory.class);

  public static final String PASSWORD_GRANT = "password";
  public static final String AUTHZ_CODE_GRANT = "authorization_code";
  public static final String DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";
  public static final String REFRESH_TOKEN_GRANT = "refresh_token";

  private final JWTProfileResolver profileResolver;
  private final ClientDetailsService clientDetailsService;
  private final DeviceCodeService deviceCodeService;
  private final IamAuthorizationCodeRepository authzCodeRepository;
  private final IamOAuthRefreshTokenRepository refreshTokenRepo;
  private final AudienceRequestValidator audienceRequestValidator;
  private final AuthorizationRequestBuilder authorizationRequestBuilder;

  public IamOAuth2RequestFactory(ClientDetailsService clientDetailsService, ScopeFilter scopeFilter,
      JWTProfileResolver profileResolver, DeviceCodeService deviceCodeService,
      IamAuthorizationCodeRepository authzCodeRepository,
      IamOAuthRefreshTokenRepository refreshTokenRepo, ClientKeyCacheService validators) {
    super(clientDetailsService);
    this.profileResolver = profileResolver;
    this.clientDetailsService = clientDetailsService;
    this.deviceCodeService = deviceCodeService;
    this.authzCodeRepository = authzCodeRepository;
    this.refreshTokenRepo = refreshTokenRepo;
    this.audienceRequestValidator = new AudienceRequestValidator();

    RequestObjectProcessor requestObjectProcessor =
        new RequestObjectProcessor(clientDetailsService, validators);

    this.authorizationRequestBuilder =
        new AuthorizationRequestBuilder(clientDetailsService, scopeFilter, requestObjectProcessor);
  }

  @Override
  public AuthorizationRequest createAuthorizationRequest(Map<String, String> inputParams) {

    Authentication authn = SecurityContextHolder.getContext().getAuthentication();
    AuthorizationRequest authzRequest = authorizationRequestBuilder.build(inputParams);

    authorizationRequestBuilder.filterRequestedScopes(inputParams, authn, authzRequest);
    audienceRequestValidator.validateAndUpdateAudienceRequest(inputParams);

    authorizationRequestBuilder.addExtensions(inputParams, authzRequest);
    authorizationRequestBuilder.applyClientDefaults(authzRequest);
    authorizationRequestBuilder.addAuthenticationMethodReferences(authn, authzRequest);

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

    profileResolver.resolveProfile(client.getScope(), request.getScope())
      .getRequestValidator()
      .validateRequest(request);

    return request;
  }

  @Override
  public TokenRequest createTokenRequest(Map<String, String> requestParameters,
      ClientDetails authenticatedClient) {

    String clientId = resolveClientId(requestParameters, authenticatedClient);
    String grantType = requestParameters.get(OAuth2Utils.GRANT_TYPE);
    Set<String> scopes = resolveScopes(requestParameters, clientId, grantType);

    return new TokenRequest(updatedTokenRequestParameters(requestParameters, authenticatedClient),
        clientId, scopes, grantType);
  }

  private String resolveClientId(Map<String, String> requestParameters,
      ClientDetails authenticatedClient) {

    String clientId = requestParameters.get(OAuth2Utils.CLIENT_ID);

    if (clientId == null) {
      return authenticatedClient.getClientId();
    }

    if (!clientId.equals(authenticatedClient.getClientId())) {
      LOG.warn("Given client ID {} does not match authenticated client {}",
          EventUtils.sanitize(clientId), EventUtils.sanitize(authenticatedClient.getClientId()));
      throw new InvalidClientException("Given client ID does not match authenticated client");
    }

    return clientId;
  }

  private Set<String> resolveScopes(Map<String, String> requestParameters, String clientId,
      String grantType) {

    Set<String> scopes = OAuth2Utils.parseParameterList(requestParameters.get(OAuth2Utils.SCOPE));

    if (scopes != null && !scopes.isEmpty()) {
      return scopes;
    }

    if (TOKEN_EXCHANGE_GRANT_TYPE.equals(grantType)) {
      throw new InvalidRequestException(
          "The scope parameter is required for a token exchange request!");
    }

    ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
    return clientDetails.getScope();
  }

  private Map<String, String> updatedTokenRequestParameters(
      Map<String, String> tokenRequestParameters, ClientDetails client) {

    Optional<Map<String, String>> authzRequestParams =
        findAuthorizationRequestParameters(tokenRequestParameters, client);

    audienceRequestValidator.validateAndUpdateAudienceRequest(tokenRequestParameters);
    authzRequestParams.ifPresent(arp -> updateTokenAudience(tokenRequestParameters, arp));

    return tokenRequestParameters;
  }

  private Optional<Map<String, String>> findAuthorizationRequestParameters(
      Map<String, String> tokenRequestParameters, ClientDetails client) {

    String grantType = tokenRequestParameters.get(OAuth2Utils.GRANT_TYPE);

    switch (grantType) {
      case AUTHZ_CODE_GRANT:
        String authzCode = tokenRequestParameters.get(IamOAuthRequestParameters.AUTHZ_CODE_KEY);
        return authzCodeRepository.findByCode(authzCode)
          .map(AuthorizationCodeEntity::getAuthenticationHolder)
          .map(holder -> holder.getRequestParameters());

      case DEVICE_CODE_GRANT:
        String deviceCode = tokenRequestParameters.get(IamOAuthRequestParameters.DEVICE_CODE_KEY);
        return deviceCodeService.findByDeviceCodeAndClientId(deviceCode, client.getClientId())
          .map(DeviceCode::getAuthenticationHolder)
          .map(holder -> holder.getRequestParameters());

      case REFRESH_TOKEN_GRANT:
        String refreshToken =
            tokenRequestParameters.get(IamOAuthRequestParameters.REFRESH_TOKEN_KEY);
        return refreshTokenRepo.findByTokenValue(refreshToken)
          .map(token -> token.getAuthenticationHolder())
          .map(holder -> holder.getRequestParameters());

      default:
        return Optional.empty();
    }
  }

  private void updateTokenAudience(Map<String, String> tokenRequestParameters,
      Map<String, String> authzRequestParams) {

    boolean hasTokenAudKey = tokenRequestParameters.containsKey(IamOAuthRequestParameters.AUD_KEY);
    boolean hasAuthzResourceParam =
        authzRequestParams.containsKey(IamOAuthRequestParameters.RESOURCE_KEY);
    boolean hasTokenResourceParam =
        tokenRequestParameters.containsKey(IamOAuthRequestParameters.RESOURCE_KEY);

    if (hasTokenAudKey && (hasAuthzResourceParam || hasTokenResourceParam)) {
      List<String> tokenResourceParams =
          splitBySpace(tokenRequestParameters.get(IamOAuthRequestParameters.AUD_KEY));
      tokenRequestParameters.put(IamOAuthRequestParameters.AUD_KEY,
          audienceRequestValidator.getAllowedResource(tokenResourceParams, authzRequestParams));
      return;
    }

    if (!hasTokenAudKey && hasAuthzResourceParam) {
      tokenRequestParameters.put(IamOAuthRequestParameters.AUD_KEY,
          authzRequestParams.get(IamOAuthRequestParameters.RESOURCE_KEY));
      // Required by RT flow after device
      tokenRequestParameters.put(IamOAuthRequestParameters.RESOURCE_KEY,
          authzRequestParams.get(IamOAuthRequestParameters.RESOURCE_KEY));
    }
  }

  public static List<String> splitBySpace(String str) {
    return AudienceRequestValidator.splitBySpace(str);
  }
}
