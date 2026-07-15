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

import java.io.Serializable;
import java.text.ParseException;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Supplier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetailsService;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.core.jwk.ClientKeyCacheService;
import it.infn.mw.iam.core.jwk.JWTSigningAndValidationService;
import it.infn.mw.iam.core.oidc.ConnectRequestParameters;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;

@SuppressWarnings("deprecation")
public class RequestObjectProcessor {

  public static final String RESPONSE_TYPE = "response_type";
  public static final String DISPLAY = "display";

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
      request.setClientId(jwt.getJWTClaimsSet().getStringClaim(ConnectRequestParameters.CLIENT_ID));
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
    applyStringClaim(claims, ConnectRequestParameters.REDIRECT_URI, request::getRedirectUri,
        request::setRedirectUri);
    applyStringClaim(claims, ConnectRequestParameters.STATE, request::getState, request::setState);
    applyStringExtensionClaim(claims, request, ConnectRequestParameters.NONCE);
    applyStringExtensionClaim(claims, request, DISPLAY);
    applyStringExtensionClaim(claims, request, ConnectRequestParameters.PROMPT);
    applyScope(claims, request);
    applyClaimsRequest(claims, request);
    applyStringExtensionClaim(claims, request, ConnectRequestParameters.LOGIN_HINT);
  }

  private void applyResponseTypes(JWTClaimsSet claims, AuthorizationRequest request)
      throws ParseException {

    Set<String> responseTypes = OAuth2Utils
      .parseParameterList(claims.getStringClaim(RESPONSE_TYPE));

    if (responseTypes.isEmpty()) {
      return;
    }

    if (!responseTypes.equals(request.getResponseTypes())) {
      logMismatch(RESPONSE_TYPE);
    }

    request.setResponseTypes(responseTypes);
  }

  private void applyScope(JWTClaimsSet claims, AuthorizationRequest request) throws ParseException {
    Set<String> scope =
        OAuth2Utils.parseParameterList(claims.getStringClaim(ConnectRequestParameters.SCOPE));

    if (scope.isEmpty()) {
      return;
    }

    if (!scope.equals(request.getScope())) {
      logMismatch(ConnectRequestParameters.SCOPE);
    }

    request.setScope(scope);
  }

  private void applyClaimsRequest(JWTClaimsSet claims, AuthorizationRequest request)
      throws ParseException {

    JsonObject claimRequest =
        parseClaimRequest(claims.getStringClaim(ConnectRequestParameters.CLAIMS));

    if (claimRequest == null) {
      return;
    }

    Serializable claimExtension = request.getExtensions().get(ConnectRequestParameters.CLAIMS);
    if (claimExtension == null
        || !claimRequest.equals(parseClaimRequest(claimExtension.toString()))) {
      logMismatch(ConnectRequestParameters.CLAIMS);
    }

    // Save the string because the object might not be Java Serializable.
    request.getExtensions().put(ConnectRequestParameters.CLAIMS, claimRequest.toString());
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