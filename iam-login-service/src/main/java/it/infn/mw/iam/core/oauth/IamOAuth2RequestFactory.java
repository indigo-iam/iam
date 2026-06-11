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
import static org.mitre.openid.connect.request.ConnectRequestParameters.AUD;
import static org.mitre.openid.connect.request.ConnectRequestParameters.CLAIMS;
import static org.mitre.openid.connect.request.ConnectRequestParameters.CODE_CHALLENGE;
import static org.mitre.openid.connect.request.ConnectRequestParameters.CODE_CHALLENGE_METHOD;
import static org.mitre.openid.connect.request.ConnectRequestParameters.LOGIN_HINT;
import static org.mitre.openid.connect.request.ConnectRequestParameters.MAX_AGE;
import static org.mitre.openid.connect.request.ConnectRequestParameters.NONCE;
import static org.mitre.openid.connect.request.ConnectRequestParameters.PROMPT;
import static org.mitre.openid.connect.request.ConnectRequestParameters.REQUEST;

import java.io.Serializable;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.mitre.jwt.encryption.service.JWTEncryptionAndDecryptionService;
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
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWEObject.State;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.EncryptedJWT;
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
  private final ClientDetailsService clientDetailsService;
  private final DeviceCodeService deviceCodeService;
  private final AuthorizationCodeRepository authzCodeRepository;
  private final OAuth2TokenEntityService tokenServices;
  private final JsonParser parser;
  private final ClientKeyCacheService validators;
  private final JWTEncryptionAndDecryptionService encryptionService;

  public IamOAuth2RequestFactory(ClientDetailsService clientDetailsService, ScopeFilter scopeFilter,
      JWTProfileResolver profileResolver, DeviceCodeService deviceCodeService,
      AuthorizationCodeRepository authzCodeRepository, OAuth2TokenEntityService tokenServices,
      ClientKeyCacheService validators, JWTEncryptionAndDecryptionService encryptionService) {
    super(clientDetailsService);
    this.clientDetailsService = clientDetailsService;
    this.scopeFilter = scopeFilter;
    this.profileResolver = profileResolver;
    this.deviceCodeService = deviceCodeService;
    this.authzCodeRepository = authzCodeRepository;
    this.tokenServices = tokenServices;
    this.validators = validators;
    this.encryptionService = encryptionService;
    this.parser = new JsonParser();
  }

  @Override
  public AuthorizationRequest createAuthorizationRequest(Map<String, String> inputParams) {

    Authentication authn = SecurityContextHolder.getContext().getAuthentication();

    if (authn != null && !(authn instanceof AnonymousAuthenticationToken)) {
      Set<String> requestedScopes =
          OAuth2Utils.parseParameterList(inputParams.get(OAuth2Utils.SCOPE));

      // scope are filtered also here to avoid authorizing them on the consent page
      inputParams.put(OAuth2Utils.SCOPE,
          joiner.join(scopeFilter.filterScopes(requestedScopes, authn)));
    }

    validateAndUpdateAudienceRequest(inputParams);

    AuthorizationRequest authzRequest = new AuthorizationRequest(inputParams,
        Collections.<String, String>emptyMap(), inputParams.get(OAuth2Utils.CLIENT_ID),
        OAuth2Utils.parseParameterList(inputParams.get(OAuth2Utils.SCOPE)), null, null, false,
        inputParams.get(OAuth2Utils.STATE), inputParams.get(OAuth2Utils.REDIRECT_URI),
        OAuth2Utils.parseParameterList(inputParams.get(OAuth2Utils.RESPONSE_TYPE)));

    // Add extension parameters to the 'extensions' map

    if (inputParams.containsKey(PROMPT)) {
      authzRequest.getExtensions().put(PROMPT, inputParams.get(PROMPT));
    }
    if (inputParams.containsKey(NONCE)) {
      authzRequest.getExtensions().put(NONCE, inputParams.get(NONCE));
    }

    if (inputParams.containsKey(CLAIMS)) {
      JsonObject claimsRequest = parseClaimRequest(inputParams.get(CLAIMS));
      if (claimsRequest != null) {
        authzRequest.getExtensions().put(CLAIMS, claimsRequest.toString());
      }
    }

    if (inputParams.containsKey(MAX_AGE)) {
      authzRequest.getExtensions().put(MAX_AGE, inputParams.get(MAX_AGE));
    }

    if (inputParams.containsKey(LOGIN_HINT)) {
      authzRequest.getExtensions().put(LOGIN_HINT, inputParams.get(LOGIN_HINT));
    }

    if (inputParams.containsKey(AUD)) {
      authzRequest.getExtensions().put(AUD, inputParams.get(AUD));
    }

    if (inputParams.containsKey(CODE_CHALLENGE)) {
      authzRequest.getExtensions().put(CODE_CHALLENGE, inputParams.get(CODE_CHALLENGE));
      if (inputParams.containsKey(CODE_CHALLENGE_METHOD)) {
        authzRequest.getExtensions()
          .put(CODE_CHALLENGE_METHOD, inputParams.get(CODE_CHALLENGE_METHOD));
      } else {
        // if the client doesn't specify a code challenge transformation method, it's "plain"
        authzRequest.getExtensions().put(CODE_CHALLENGE_METHOD, PKCEAlgorithm.plain.getName());
      }

    }

    if (inputParams.containsKey(REQUEST)) {
      authzRequest.getExtensions().put(REQUEST, inputParams.get(REQUEST));
      processRequestObject(inputParams.get(REQUEST), authzRequest);
    }

    if (authzRequest.getClientId() != null) {
      try {
        ClientDetailsEntity client = (ClientDetailsEntity) clientDetailsService
          .loadClientByClientId(authzRequest.getClientId());

        if ((authzRequest.getScope() == null || authzRequest.getScope().isEmpty())) {
          Set<String> clientScopes = client.getScope();
          authzRequest.setScope(clientScopes);
        }

        if (authzRequest.getExtensions().get(MAX_AGE) == null
            && client.getDefaultMaxAge() != null) {
          authzRequest.getExtensions().put(MAX_AGE, client.getDefaultMaxAge().toString());
        }
      } catch (OAuth2Exception e) {
        LOG.error("Caught OAuth2 exception trying to test client scopes and max age:", e);
      }
    }

    Set<IamAuthenticationMethodReference> amrSet;
    if (authn instanceof ExtendedAuthenticationToken extendedToken) {
      amrSet = extendedToken.getAuthenticationMethodReferences();
      processToken(amrSet, authzRequest);
    } else if (authn instanceof AbstractExternalAuthenticationToken<?> externalToken) {
      amrSet = externalToken.getAuthenticationMethodReferences();
      processToken(amrSet, authzRequest);
    }

    return authzRequest;
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

  private void processRequestObject(String jwtString, AuthorizationRequest request) {

    // parse the request object
    try {
      JWT jwt = JWTParser.parse(jwtString);

      if (jwt instanceof SignedJWT) {
        // it's a signed JWT, check the signature

        SignedJWT signedJwt = (SignedJWT) jwt;

        // need to check clientId first so that we can load the client to check other fields
        if (request.getClientId() == null) {
          request.setClientId(signedJwt.getJWTClaimsSet().getStringClaim("client_id"));
        }

        ClientDetailsEntity client = (ClientDetailsEntity)
            clientDetailsService.loadClientByClientId(request.getClientId());

        if (client == null) {
          throw new InvalidClientException("Client not found: " + request.getClientId());
        }


        JWSAlgorithm alg = signedJwt.getHeader().getAlgorithm();

        if (client.getRequestObjectSigningAlg() == null
            || !client.getRequestObjectSigningAlg().equals(alg)) {
          throw new InvalidClientException("Client's registered request object signing algorithm ("
              + client.getRequestObjectSigningAlg()
              + ") does not match request object's actual algorithm (" + alg.getName() + ")");
        }

        JWTSigningAndValidationService validator = validators.getValidator(client, alg);

        if (validator == null) {
          throw new InvalidClientException("Unable to create signature validator for client "
              + client + " and algorithm " + alg);
        }

        if (!validator.validateSignature(signedJwt)) {
          throw new InvalidClientException(
              "Signature did not validate for presented JWT request object.");
        }

      } else if (jwt instanceof PlainJWT) {
        PlainJWT plainJwt = (PlainJWT) jwt;

        // need to check clientId first so that we can load the client to check other fields
        if (request.getClientId() == null) {
          request.setClientId(plainJwt.getJWTClaimsSet().getStringClaim("client_id"));
        }

        ClientDetailsEntity client = (ClientDetailsEntity)
            clientDetailsService.loadClientByClientId(request.getClientId());

        if (client == null) {
          throw new InvalidClientException("Client not found: " + request.getClientId());
        }

        if (client.getRequestObjectSigningAlg() == null) {
          throw new InvalidClientException(
              "Client is not registered for unsigned request objects (no request_object_signing_alg registered)");
        } else if (!client.getRequestObjectSigningAlg().equals(Algorithm.NONE)) {
          throw new InvalidClientException(
              "Client is not registered for unsigned request objects (request_object_signing_alg is "
                  + client.getRequestObjectSigningAlg() + ")");
        }

        // if we got here, we're OK, keep processing

      } else if (jwt instanceof EncryptedJWT) {

        EncryptedJWT encryptedJWT = (EncryptedJWT) jwt;

        // decrypt the jwt if we can

        encryptionService.decryptJwt(encryptedJWT);

        // TODO: what if the content is a signed JWT? (#525)

        if (!encryptedJWT.getState().equals(State.DECRYPTED)) {
          throw new InvalidClientException("Unable to decrypt the request object");
        }

        // need to check clientId first so that we can load the client to check other fields
        if (request.getClientId() == null) {
          request.setClientId(encryptedJWT.getJWTClaimsSet().getStringClaim("client_id"));
        }

        ClientDetailsEntity client = (ClientDetailsEntity)
            clientDetailsService.loadClientByClientId(request.getClientId());

        if (client == null) {
          throw new InvalidClientException("Client not found: " + request.getClientId());
        }
      }

      /*
       * NOTE: Claims inside the request object always take precedence over those in the parameter
       * map.
       */

      // now that we've got the JWT, and it's been parsed, validated, and/or decrypted, we can
      // process the claims

      JWTClaimsSet claims = jwt.getJWTClaimsSet();

      Set<String> responseTypes =
          OAuth2Utils.parseParameterList(claims.getStringClaim("response_type"));
      if (!responseTypes.isEmpty()) {
        if (!responseTypes.equals(request.getResponseTypes())) {
          LOG.info(
              "Mismatch between request object and regular parameter for response_type, using request object");
        }
        request.setResponseTypes(responseTypes);
      }

      String redirectUri = claims.getStringClaim("redirect_uri");
      if (redirectUri != null) {
        if (!redirectUri.equals(request.getRedirectUri())) {
          LOG.info(
              "Mismatch between request object and regular parameter for redirect_uri, using request object");
        }
        request.setRedirectUri(redirectUri);
      }

      String state = claims.getStringClaim("state");
      if (state != null) {
        if (!state.equals(request.getState())) {
          LOG.info(
              "Mismatch between request object and regular parameter for state, using request object");
        }
        request.setState(state);
      }

      String nonce = claims.getStringClaim(NONCE);
      if (nonce != null) {
        if (!nonce.equals(request.getExtensions().get(NONCE))) {
          LOG.info(
              "Mismatch between request object and regular parameter for nonce, using request object");
        }
        request.getExtensions().put(NONCE, nonce);
      }

      String display = claims.getStringClaim("display");
      if (display != null) {
        if (!display.equals(request.getExtensions().get("display"))) {
          LOG.info(
              "Mismatch between request object and regular parameter for display, using request object");
        }
        request.getExtensions().put("display", display);
      }

      String prompt = claims.getStringClaim(PROMPT);
      if (prompt != null) {
        if (!prompt.equals(request.getExtensions().get(PROMPT))) {
          LOG.info(
              "Mismatch between request object and regular parameter for prompt, using request object");
        }
        request.getExtensions().put(PROMPT, prompt);
      }

      Set<String> scope = OAuth2Utils.parseParameterList(claims.getStringClaim("scope"));
      if (!scope.isEmpty()) {
        if (!scope.equals(request.getScope())) {
          LOG.info(
              "Mismatch between request object and regular parameter for scope, using request object");
        }
        request.setScope(scope);
      }

      JsonObject claimRequest = parseClaimRequest(claims.getStringClaim(CLAIMS));
      if (claimRequest != null) {
        Serializable claimExtension = request.getExtensions().get(CLAIMS);
        if (claimExtension == null
            || !claimRequest.equals(parseClaimRequest(claimExtension.toString()))) {
          LOG.info(
              "Mismatch between request object and regular parameter for claims, using request object");
        }
        // we save the string because the object might not be a Java Serializable, and we can parse
        // it easily enough anyway
        request.getExtensions().put(CLAIMS, claimRequest.toString());
      }

      String loginHint = claims.getStringClaim(LOGIN_HINT);
      if (loginHint != null) {
        if (!loginHint.equals(request.getExtensions().get(LOGIN_HINT))) {
          LOG.info(
              "Mistmatch between request object and regular parameter for login_hint, using requst object");
        }
        request.getExtensions().put(LOGIN_HINT, loginHint);
      }

    } catch (ParseException e) {
      LOG.error("ParseException while parsing RequestObject:", e);
    }
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

    profileResolver.resolveProfile(client.getScope(), request.getScope())
      .getRequestValidator()
      .validateRequest(request);

    return request;
  }


  @Override
  public TokenRequest createTokenRequest(Map<String, String> requestParameters,
      ClientDetails authenticatedClient) {

    String clientId = requestParameters.get(OAuth2Utils.CLIENT_ID);
    if (clientId == null) {
      clientId = authenticatedClient.getClientId();
    } else {
      if (!clientId.equals(authenticatedClient.getClientId())) {
        LOG.warn("Given client ID {} does not match authenticated client {}",
            EventUtils.sanitize(clientId), EventUtils.sanitize(authenticatedClient.getClientId()));
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
        clientId, scopes, grantType);
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
