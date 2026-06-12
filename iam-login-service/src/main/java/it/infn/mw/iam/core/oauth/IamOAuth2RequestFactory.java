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
import static org.mitre.openid.connect.request.ConnectRequestParameters.AUD;
import static org.mitre.openid.connect.request.ConnectRequestParameters.CLAIMS;
import static org.mitre.openid.connect.request.ConnectRequestParameters.CLIENT_ID;
import static org.mitre.openid.connect.request.ConnectRequestParameters.CODE_CHALLENGE;
import static org.mitre.openid.connect.request.ConnectRequestParameters.CODE_CHALLENGE_METHOD;
import static org.mitre.openid.connect.request.ConnectRequestParameters.DISPLAY;
import static org.mitre.openid.connect.request.ConnectRequestParameters.LOGIN_HINT;
import static org.mitre.openid.connect.request.ConnectRequestParameters.MAX_AGE;
import static org.mitre.openid.connect.request.ConnectRequestParameters.NONCE;
import static org.mitre.openid.connect.request.ConnectRequestParameters.PROMPT;
import static org.mitre.openid.connect.request.ConnectRequestParameters.REDIRECT_URI;
import static org.mitre.openid.connect.request.ConnectRequestParameters.REQUEST;
import static org.mitre.openid.connect.request.ConnectRequestParameters.RESPONSE_TYPE;
import static org.mitre.openid.connect.request.ConnectRequestParameters.SCOPE;
import static org.mitre.openid.connect.request.ConnectRequestParameters.STATE;

import java.io.Serializable;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mitre.jwt.signer.service.impl.ClientKeyCacheService;
import org.mitre.oauth2.model.AuthorizationCodeEntity;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.DeviceCode;
import org.mitre.oauth2.model.PKCEAlgorithm;
import org.mitre.oauth2.repository.AuthorizationCodeRepository;
import org.mitre.oauth2.service.DeviceCodeService;
import org.mitre.oauth2.service.OAuth2TokenEntityService;
import org.mitre.openid.connect.web.AuthenticationTimeStamper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Joiner;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.audit.events.utils.EventUtils;
import it.infn.mw.iam.authn.AbstractExternalAuthenticationToken;
import it.infn.mw.iam.authn.multi_factor_authentication.IamAuthenticationMethodReference;
import it.infn.mw.iam.core.ExtendedAuthenticationToken;
import it.infn.mw.iam.core.error.InvalidResourceError;
import it.infn.mw.iam.core.oauth.profile.JWTProfileResolver;
import it.infn.mw.iam.core.oauth.scope.pdp.ScopeFilter;

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
  private final AuthorizationCodeRepository authzCodeRepository;
  private final OAuth2TokenEntityService tokenServices;
  private final AudienceRequestValidator audienceRequestValidator;
  private final AuthorizationRequestBuilder authorizationRequestBuilder;

  public IamOAuth2RequestFactory(ClientDetailsService clientDetailsService, ScopeFilter scopeFilter,
      JWTProfileResolver profileResolver, DeviceCodeService deviceCodeService,
      AuthorizationCodeRepository authzCodeRepository, OAuth2TokenEntityService tokenServices,
      ClientKeyCacheService validators) {
    super(clientDetailsService);
    this.profileResolver = profileResolver;
    this.clientDetailsService = clientDetailsService;
    this.deviceCodeService = deviceCodeService;
    this.authzCodeRepository = authzCodeRepository;
    this.tokenServices = tokenServices;
    this.audienceRequestValidator = new AudienceRequestValidator();

    RequestObjectProcessor requestObjectProcessor =
        new RequestObjectProcessor(clientDetailsService, validators);

    this.authorizationRequestBuilder =
        new AuthorizationRequestBuilder(clientDetailsService, scopeFilter, requestObjectProcessor);
  }

  @Override
  public AuthorizationRequest createAuthorizationRequest(Map<String, String> inputParams) {

    Authentication authn = SecurityContextHolder.getContext().getAuthentication();

    authorizationRequestBuilder.filterRequestedScopes(inputParams, authn);
    audienceRequestValidator.validateAndUpdateAudienceRequest(inputParams);

    AuthorizationRequest authzRequest = authorizationRequestBuilder.build(inputParams);

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
        return Optional
          .ofNullable(authzCodeRepository
            .getByCode(tokenRequestParameters.get(IamOAuthRequestParameters.AUTHZ_CODE_KEY)))
          .map(AuthorizationCodeEntity::getAuthenticationHolder)
          .map(holder -> holder.getRequestParameters());

      case DEVICE_CODE_GRANT:
        return Optional
          .ofNullable(deviceCodeService.findDeviceCode(
              tokenRequestParameters.get(IamOAuthRequestParameters.DEVICE_CODE_KEY), client))
          .map(DeviceCode::getAuthenticationHolder)
          .map(holder -> holder.getRequestParameters());

      case REFRESH_TOKEN_GRANT:
        return Optional
          .ofNullable(tokenServices.getRefreshToken(
              tokenRequestParameters.get(IamOAuthRequestParameters.REFRESH_TOKEN_KEY)))
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

  public static void validateUrl(String url) {
    AudienceRequestValidator.validateUrl(url);
  }

  public static List<String> splitBySpace(String str) {
    return AudienceRequestValidator.splitBySpace(str);
  }
}


@SuppressWarnings("deprecation")
class AuthorizationRequestBuilder {

  private static final Logger LOG = LoggerFactory.getLogger(AuthorizationRequestBuilder.class);

  private final ScopeFilter scopeFilter;
  private final Joiner joiner = Joiner.on(' ');
  private final ClientDetailsService clientDetailsService;
  private final RequestObjectProcessor requestObjectProcessor;
  private final JsonParser parser = new JsonParser();

  AuthorizationRequestBuilder(ClientDetailsService clientDetailsService, ScopeFilter scopeFilter,
      RequestObjectProcessor requestObjectProcessor) {
    this.clientDetailsService = clientDetailsService;
    this.scopeFilter = scopeFilter;
    this.requestObjectProcessor = requestObjectProcessor;
  }

  void filterRequestedScopes(Map<String, String> inputParams, Authentication authn) {
    if (authn == null || authn instanceof AnonymousAuthenticationToken) {
      return;
    }

    Set<String> requestedScopes =
        OAuth2Utils.parseParameterList(inputParams.get(OAuth2Utils.SCOPE));

    // scopes are filtered also here to avoid authorizing them on the consent page
    inputParams.put(OAuth2Utils.SCOPE,
        joiner.join(scopeFilter.filterScopes(requestedScopes, authn)));
  }

  AuthorizationRequest build(Map<String, String> inputParams) {
    return new AuthorizationRequest(inputParams, Collections.emptyMap(),
        inputParams.get(OAuth2Utils.CLIENT_ID),
        OAuth2Utils.parseParameterList(inputParams.get(OAuth2Utils.SCOPE)), null, null, false,
        inputParams.get(OAuth2Utils.STATE), inputParams.get(OAuth2Utils.REDIRECT_URI),
        OAuth2Utils.parseParameterList(inputParams.get(OAuth2Utils.RESPONSE_TYPE)));
  }

  void addExtensions(Map<String, String> inputParams, AuthorizationRequest authzRequest) {
    copyExtension(inputParams, authzRequest, PROMPT);
    copyExtension(inputParams, authzRequest, NONCE);
    copyExtension(inputParams, authzRequest, MAX_AGE);
    copyExtension(inputParams, authzRequest, LOGIN_HINT);
    copyExtension(inputParams, authzRequest, AUD);
    addClaimsExtension(inputParams, authzRequest);
    addPkceExtensions(inputParams, authzRequest);
    addRequestObjectExtension(inputParams, authzRequest);
  }

  void applyClientDefaults(AuthorizationRequest authzRequest) {
    if (authzRequest.getClientId() == null) {
      return;
    }

    try {
      ClientDetailsEntity client = (ClientDetailsEntity) clientDetailsService
        .loadClientByClientId(authzRequest.getClientId());

      applyDefaultScopes(authzRequest, client);
      applyDefaultMaxAge(authzRequest, client);

    } catch (OAuth2Exception e) {
      LOG.error("Caught OAuth2 exception trying to test client scopes and max age:", e);
    }
  }

  void addAuthenticationMethodReferences(Authentication authn, AuthorizationRequest authzRequest) {
    if (authn instanceof ExtendedAuthenticationToken extendedToken) {
      processToken(extendedToken.getAuthenticationMethodReferences(), authzRequest);
      return;
    }

    if (authn instanceof AbstractExternalAuthenticationToken<?> externalToken) {
      processToken(externalToken.getAuthenticationMethodReferences(), authzRequest);
    }
  }

  private void copyExtension(Map<String, String> inputParams, AuthorizationRequest authzRequest,
      String key) {
    if (inputParams.containsKey(key)) {
      authzRequest.getExtensions().put(key, inputParams.get(key));
    }
  }

  private void addClaimsExtension(Map<String, String> inputParams,
      AuthorizationRequest authzRequest) {
    if (!inputParams.containsKey(CLAIMS)) {
      return;
    }

    JsonObject claimsRequest = parseClaimRequest(inputParams.get(CLAIMS));
    if (claimsRequest != null) {
      authzRequest.getExtensions().put(CLAIMS, claimsRequest.toString());
    }
  }

  private void addPkceExtensions(Map<String, String> inputParams,
      AuthorizationRequest authzRequest) {
    if (!inputParams.containsKey(CODE_CHALLENGE)) {
      return;
    }

    authzRequest.getExtensions().put(CODE_CHALLENGE, inputParams.get(CODE_CHALLENGE));
    authzRequest.getExtensions()
      .put(CODE_CHALLENGE_METHOD,
          inputParams.getOrDefault(CODE_CHALLENGE_METHOD, PKCEAlgorithm.plain.getName()));
  }

  private void addRequestObjectExtension(Map<String, String> inputParams,
      AuthorizationRequest authzRequest) {
    if (inputParams.containsKey(REQUEST)) {
      authzRequest.getExtensions().put(REQUEST, inputParams.get(REQUEST));
      requestObjectProcessor.processRequestObject(inputParams.get(REQUEST), authzRequest);
    }
  }

  private void applyDefaultScopes(AuthorizationRequest authzRequest, ClientDetailsEntity client) {
    if (authzRequest.getScope() == null || authzRequest.getScope().isEmpty()) {
      authzRequest.setScope(client.getScope());
    }
  }

  private void applyDefaultMaxAge(AuthorizationRequest authzRequest, ClientDetailsEntity client) {
    if (authzRequest.getExtensions().get(MAX_AGE) == null && client.getDefaultMaxAge() != null) {
      authzRequest.getExtensions().put(MAX_AGE, client.getDefaultMaxAge().toString());
    }
  }

  private JsonObject parseClaimRequest(String claimRequestString) {
    if (claimRequestString == null || claimRequestString.isEmpty()) {
      return null;
    }

    JsonElement el = parser.parse(claimRequestString);
    if (el != null && el.isJsonObject()) {
      return el.getAsJsonObject();
    }

    return null;
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
}


@SuppressWarnings("deprecation")
class RequestObjectProcessor {

  private static final Logger LOG = LoggerFactory.getLogger(RequestObjectProcessor.class);

  private final ClientDetailsService clientDetailsService;
  private final ClientKeyCacheService validators;
  private final JsonParser parser = new JsonParser();

  RequestObjectProcessor(ClientDetailsService clientDetailsService,
      ClientKeyCacheService validators) {
    this.clientDetailsService = clientDetailsService;
    this.validators = validators;
  }

  void processRequestObject(String jwtString, AuthorizationRequest request) {
    try {
      JWT jwt = parseAndValidateJwt(jwtString, request);
      applyClaims(jwt.getJWTClaimsSet(), request);
    } catch (ParseException e) {
      LOG.error("ParseException while parsing RequestObject:", e);
    }
  }

  private JWT parseAndValidateJwt(String jwtString, AuthorizationRequest request)
      throws ParseException {

    JWT jwt = JWTParser.parse(jwtString);

    if (jwt instanceof SignedJWT signedJwt) {
      processSignedJwt(signedJwt, request);
      return signedJwt;
    }
    if (jwt instanceof PlainJWT plainJwt) {
      processPlainJwt(plainJwt, request);
      return plainJwt;
    }
    throw new InvalidRequestException("Invalid Request Object JWT");
  }

  private void processSignedJwt(SignedJWT signedJwt, AuthorizationRequest request)
      throws ParseException {

    ClientDetailsEntity client = loadClientFromJwtIfNeeded(signedJwt, request);
    JWSAlgorithm alg = signedJwt.getHeader().getAlgorithm();

    validateSigningAlgorithm(client, alg);
    validateSignature(signedJwt, client, alg);
  }

  private void processPlainJwt(PlainJWT plainJwt, AuthorizationRequest request)
      throws ParseException {

    ClientDetailsEntity client = loadClientFromJwtIfNeeded(plainJwt, request);
    validateUnsignedRequestObjectAllowed(client);
  }

  private ClientDetailsEntity loadClientFromJwtIfNeeded(JWT jwt, AuthorizationRequest request)
      throws ParseException {

    if (request.getClientId() == null) {
      request.setClientId(jwt.getJWTClaimsSet().getStringClaim(CLIENT_ID));
    }

    ClientDetailsEntity client =
        (ClientDetailsEntity) clientDetailsService.loadClientByClientId(request.getClientId());

    if (client == null) {
      throw new InvalidClientException("Client not found: " + request.getClientId());
    }

    return client;
  }

  private void validateSigningAlgorithm(ClientDetailsEntity client, JWSAlgorithm alg) {
    if (client.getRequestObjectSigningAlg() == null
        || !client.getRequestObjectSigningAlg().equals(alg)) {
      throw new InvalidClientException("Client's registered request object signing algorithm ("
          + client.getRequestObjectSigningAlg()
          + ") does not match request object's actual algorithm (" + alg.getName() + ")");
    }
  }

  private void validateSignature(SignedJWT signedJwt, ClientDetailsEntity client,
      JWSAlgorithm alg) {

    JWTSigningAndValidationService validator = validators.getValidator(client, alg);

    if (validator == null) {
      throw new InvalidClientException(
          "Unable to create signature validator for client " + client + " and algorithm " + alg);
    }

    if (!validator.validateSignature(signedJwt)) {
      throw new InvalidClientException(
          "Signature did not validate for presented JWT request object.");
    }
  }

  private void validateUnsignedRequestObjectAllowed(ClientDetailsEntity client) {
    if (client.getRequestObjectSigningAlg() != null) {
      throw new InvalidClientException(
          "Client is not registered for unsigned request objects (request_object_signing_alg is "
              + client.getRequestObjectSigningAlg() + ")");
    }
  }

  private void applyClaims(JWTClaimsSet claims, AuthorizationRequest request)
      throws ParseException {

    applyResponseTypes(claims, request);
    applyStringClaim(claims, REDIRECT_URI, request::getRedirectUri, request::setRedirectUri);
    applyStringClaim(claims, STATE, request::getState, request::setState);
    applyStringExtensionClaim(claims, request, NONCE);
    applyStringExtensionClaim(claims, request, DISPLAY);
    applyStringExtensionClaim(claims, request, PROMPT);
    applyScope(claims, request);
    applyClaimsRequest(claims, request);
    applyStringExtensionClaim(claims, request, LOGIN_HINT);
  }

  private void applyResponseTypes(JWTClaimsSet claims, AuthorizationRequest request)
      throws ParseException {

    Set<String> responseTypes =
        OAuth2Utils.parseParameterList(claims.getStringClaim(RESPONSE_TYPE));

    if (responseTypes.isEmpty()) {
      return;
    }

    if (!responseTypes.equals(request.getResponseTypes())) {
      logMismatch(RESPONSE_TYPE);
    }

    request.setResponseTypes(responseTypes);
  }

  private void applyScope(JWTClaimsSet claims, AuthorizationRequest request) throws ParseException {
    Set<String> scope = OAuth2Utils.parseParameterList(claims.getStringClaim(SCOPE));

    if (scope.isEmpty()) {
      return;
    }

    if (!scope.equals(request.getScope())) {
      logMismatch(SCOPE);
    }

    request.setScope(scope);
  }

  private void applyClaimsRequest(JWTClaimsSet claims, AuthorizationRequest request)
      throws ParseException {

    JsonObject claimRequest = parseClaimRequest(claims.getStringClaim(CLAIMS));

    if (claimRequest == null) {
      return;
    }

    Serializable claimExtension = request.getExtensions().get(CLAIMS);
    if (claimExtension == null
        || !claimRequest.equals(parseClaimRequest(claimExtension.toString()))) {
      logMismatch(CLAIMS);
    }

    // Save the string because the object might not be Java Serializable.
    request.getExtensions().put(CLAIMS, claimRequest.toString());
  }

  private void applyStringExtensionClaim(JWTClaimsSet claims, AuthorizationRequest request,
      String claimName) throws ParseException {

    applyStringClaim(claims, claimName, () -> (String) request.getExtensions().get(claimName),
        value -> request.getExtensions().put(claimName, value));
  }

  private void applyStringClaim(JWTClaimsSet claims, String claimName,
      Supplier<String> currentValue, Consumer<String> updater) throws ParseException {

    String claimValue = claims.getStringClaim(claimName);

    if (claimValue == null) {
      return;
    }

    if (!claimValue.equals(currentValue.get())) {
      logMismatch(claimName);
    }

    updater.accept(claimValue);
  }

  private JsonObject parseClaimRequest(String claimRequestString) {
    if (claimRequestString == null || claimRequestString.isEmpty()) {
      return null;
    }

    JsonElement el = parser.parse(claimRequestString);
    if (el != null && el.isJsonObject()) {
      return el.getAsJsonObject();
    }

    return null;
  }

  private void logMismatch(String parameterName) {
    LOG.info("Mismatch between request object and regular parameter for {}, using request object",
        parameterName);
  }
}


class AudienceRequestValidator {

  void validateAndUpdateAudienceRequest(Map<String, String> params) {

    if (params.containsKey(IamOAuthRequestParameters.RESOURCE_KEY)) {
      List<String> resourceParams =
          splitBySpace(params.get(IamOAuthRequestParameters.RESOURCE_KEY));
      resourceParams.forEach(AudienceRequestValidator::validateUrl);
    }

    Optional<String> audience = Optional.ofNullable(getFirstNotEmptyAudience(params));
    audience.ifPresent(aud -> params.put(IamOAuthRequestParameters.AUD_KEY, aud));
  }

  String getAllowedResource(List<String> tokenResourceParams,
      Map<String, String> authzRequestParams) {

    List<String> authzResourceParams =
        splitBySpace(authzRequestParams.get(IamOAuthRequestParameters.RESOURCE_KEY));
    tokenResourceParams.retainAll(authzResourceParams);

    String allowedResource = String.join(" ", tokenResourceParams);
    if (allowedResource.isEmpty()) {
      throw new InvalidResourceError("The requested resource was not originally granted");
    }

    return allowedResource;
  }

  private String getFirstNotEmptyAudience(Map<String, String> params) {
    return IamOAuthRequestParameters.AUD_KEYS.stream()
      .map(params::get)
      .filter(aud -> aud != null && !aud.isEmpty())
      .findFirst()
      .orElse(null);
  }

  static void validateUrl(String url) {
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

  static List<String> splitBySpace(String str) {
    if (str == null) {
      return new ArrayList<>();
    }
    return Pattern.compile(" ").splitAsStream(str).collect(Collectors.toList());
  }
}
