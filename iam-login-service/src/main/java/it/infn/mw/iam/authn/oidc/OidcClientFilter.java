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
package it.infn.mw.iam.authn.oidc;

import static it.infn.mw.iam.authn.util.SessionUtils.getStoredSessionString;

import java.io.IOException;
import java.text.ParseException;
import java.util.Date;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mitre.oauth2.model.RegisteredClient;
import org.mitre.openid.connect.client.OIDCAuthenticationFilter;
import org.mitre.openid.connect.config.ServerConfiguration;
import org.mitre.openid.connect.model.PendingOIDCAuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import com.google.common.base.Strings;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

/**
 * A slightly modified version of mitreid client filter that allows to provide a custom
 * {@link ClientHttpRequestFactory} object. This is needed to accomodate SSL connections to
 * providers that use EUGridPMA certificates.
 *
 */
@SuppressWarnings("deprecation")
public class OidcClientFilter extends OIDCAuthenticationFilter {

  public static class OidcProviderConfiguration {

    public OidcProviderConfiguration(ServerConfiguration sc, RegisteredClient cc) {
      this.serverConfig = sc;
      this.clientConfig = cc;
    }

    ServerConfiguration serverConfig;
    RegisteredClient clientConfig;
  }

  public static final Logger LOG = LoggerFactory.getLogger(OidcClientFilter.class);

  OidcTokenRequestor tokenRequestor;

  // Allow for time sync issues by having a window of X seconds.
  private int timeSkewAllowance = 300;

  private void validateState(HttpServletRequest request, HttpServletResponse response) {

    HttpSession session = request.getSession();

    // check for state, if it doesn't match we bail early
    String storedState = getStoredState(session);
    String requestState = request.getParameter("state");

    if (storedState == null || !storedState.equals(requestState)) {
      throw new AuthenticationServiceException(
          "State parameter mismatch on return. Expected " + storedState + " got " + requestState);
    }
  }


  protected OidcProviderConfiguration lookupProvider(HttpServletRequest request) {

    String issuer = getStoredSessionString(request.getSession(), ISSUER_SESSION_VARIABLE);
    if (issuer == null) {
      throw new AuthenticationServiceException("Issuer not found in session.");
    }
    ServerConfiguration serverConfig =
        getServerConfigurationService().getServerConfiguration(issuer);

    if (serverConfig == null) {
      throw new AuthenticationServiceException("Unknow OpenID provider :" + issuer);
    }

    RegisteredClient clientConfig =
        getClientConfigurationService().getClientConfiguration(serverConfig);

    if (clientConfig == null) {
      throw new AuthenticationServiceException(
          "Client configuration not found for OpenID provider :" + issuer);
    }

    return new OidcProviderConfiguration(serverConfig, clientConfig);

  }

  protected MultiValueMap<String, String> initTokenRequestParameters(HttpServletRequest request,
      OidcProviderConfiguration config) {

    MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
    form.add("grant_type", "authorization_code");
    form.add("code", request.getParameter("code"));

    form.setAll(getAuthRequestOptionsService().getTokenOptions(config.serverConfig,
        config.clientConfig, request));

    String redirectUri = getStoredSessionString(request.getSession(), REDIRECT_URI_SESION_VARIABLE);

    if (redirectUri != null) {
      form.add("redirect_uri", redirectUri);
    }

    return form;

  }

  protected JsonObject jsonStringSanityChecks(String jsonString) {

    JsonElement jsonRoot = new JsonParser().parse(jsonString);
    if (!jsonRoot.isJsonObject()) {
      throw new AuthenticationServiceException(
          "Token Endpoint did not return a JSON object: " + jsonRoot);
    }

    return jsonRoot.getAsJsonObject();
  }

  private JWT parseToken(String tokenValue) {

    try {
      return JWTParser.parse(tokenValue);

    } catch (ParseException e) {
      throw new AuthenticationServiceException("ID Token parse error");
    }
  }

  @Override
  protected void handleError(HttpServletRequest request, HttpServletResponse response)
      throws IOException {

    throw new OidcClientError("External authentication error", request.getParameter("error"),
        request.getParameter("error_description"), request.getParameter("error_uri"));

  }

  @Override
  protected Authentication handleAuthorizationCodeResponse(HttpServletRequest request,
      HttpServletResponse response) {

    validateState(request, response);
    OidcProviderConfiguration config = lookupProvider(request);

    String tokenResponseString = null;

    try {

      tokenResponseString =
          tokenRequestor.requestTokens(config, initTokenRequestParameters(request, config));

    } catch (OidcClientError e) {
      LOG.error("Error executing token request against endpoint {}: {}",
          config.serverConfig.getTokenEndpointUri(), e.getMessage(), e);
      throw e;
    }

    LOG.debug("Token Endpoint returned string: {}", tokenResponseString);

    JsonObject tokenResponse = jsonStringSanityChecks(tokenResponseString);

    String accessTokenValue = null;
    String idTokenValue = null;
    String refreshTokenValue = null;

    if (tokenResponse.has("access_token")) {
      accessTokenValue = tokenResponse.get("access_token").getAsString();
    } else {
      throw new AuthenticationServiceException(
          "Token Endpoint did not return an access_token. Response: " + tokenResponseString);
    }

    if (tokenResponse.has("id_token")) {
      idTokenValue = tokenResponse.get("id_token").getAsString();
    } else {
      logger.error("Token Endpoint did not return an id_token");
      throw new AuthenticationServiceException("Token Endpoint did not return an id_token");
    }

    if (tokenResponse.has("refresh_token")) {
      refreshTokenValue = tokenResponse.get("refresh_token").getAsString();
    }

    JWT idToken = parseToken(idTokenValue);
    JWTClaimsSet idClaims = parseClaims(idToken);

    validateSignature(idToken, config);
    validateClaims(request.getSession(), idToken, idClaims, config);

    PendingOIDCAuthenticationToken oidcToken =
        new PendingOIDCAuthenticationToken(idClaims.getSubject(), idClaims.getIssuer(),
            config.serverConfig, idToken, accessTokenValue, refreshTokenValue);

    return getAuthenticationManager().authenticate(oidcToken);

  }

  private JWTClaimsSet parseClaims(JWT idToken) {

    try {
      return idToken.getJWTClaimsSet();
    } catch (ParseException e) {
      throw new AuthenticationServiceException("Error parsing JWT claims: " + e.getMessage());
    }

  }

  protected void validateSignature(JWT idToken, OidcProviderConfiguration config) {

    Algorithm tokenAlg = idToken.getHeader().getAlgorithm();

    Algorithm clientAlg = config.clientConfig.getIdTokenSignedResponseAlg();

    JWTSigningAndValidationService jwtValidator = null;

    if (clientAlg != null && !clientAlg.equals(tokenAlg)) {
      throw new AuthenticationServiceException(
          "Token algorithm " + tokenAlg + " does not match expected algorithm " + clientAlg);
    }

    if (idToken instanceof PlainJWT) {

      if (clientAlg == null) {
        throw new AuthenticationServiceException(
            "Unsigned ID tokens can only be used if explicitly configured in client.");
      }

      if (tokenAlg != null && !tokenAlg.equals(Algorithm.NONE)) {
        throw new AuthenticationServiceException(
            "Unsigned token received, expected signature with " + tokenAlg);
      }
    } else if (idToken instanceof SignedJWT) {

      SignedJWT signedIdToken = (SignedJWT) idToken;

      if (tokenAlg.equals(JWSAlgorithm.HS256) || tokenAlg.equals(JWSAlgorithm.HS384)
          || tokenAlg.equals(JWSAlgorithm.HS512)) {

        // generate one based on client secret
        jwtValidator =
            getSymmetricCacheService().getSymmetricValidtor(config.clientConfig.getClient());
      } else {
        // otherwise load from the server's public key
        jwtValidator = getValidationServices().getValidator(config.serverConfig.getJwksUri());
      }

      if (jwtValidator != null) {
        if (!jwtValidator.validateSignature(signedIdToken)) {
          throw new AuthenticationServiceException("Signature validation failed");
        }
      } else {
        logger.error("No validation service found. Skipping signature validation");
        throw new AuthenticationServiceException(
            "Unable to find an appropriate signature validator for ID Token.");
      }
    }

  }

  protected void validateClaims(HttpSession session, JWT idToken, JWTClaimsSet idClaims,
      OidcProviderConfiguration config) {

    // check the issuer
    if (idClaims.getIssuer() == null) {

      throw new AuthenticationServiceException("Id Token Issuer is null");

    } else if (!idClaims.getIssuer().equals(config.serverConfig.getIssuer())) {
      throw new AuthenticationServiceException("Issuers do not match, expected "
          + config.serverConfig.getIssuer() + " got " + idClaims.getIssuer());
    }

    // check expiration
    if (idClaims.getExpirationTime() == null) {

      throw new AuthenticationServiceException("Id Token does not have required expiration claim");

    } else {

      Date now = new Date(System.currentTimeMillis() - (timeSkewAllowance * 1000));

      if (now.after(idClaims.getExpirationTime())) {
        throw new AuthenticationServiceException(
            "Id Token is expired: " + idClaims.getExpirationTime());
      }
    }

    // check not before
    if (idClaims.getNotBeforeTime() != null) {

      Date now = new Date(System.currentTimeMillis() + (timeSkewAllowance * 1000));

      if (now.before(idClaims.getNotBeforeTime())) {
        throw new AuthenticationServiceException(
            "Id Token not valid until: " + idClaims.getNotBeforeTime());
      }
    }

    // check issued at
    if (idClaims.getIssueTime() == null) {
      throw new AuthenticationServiceException("Id Token does not have required issued-at claim");
    } else {
      // since it's not null, see if it was issued in the future
      Date now = new Date(System.currentTimeMillis() + (timeSkewAllowance * 1000));

      if (now.before(idClaims.getIssueTime())) {
        throw new AuthenticationServiceException(
            "Id Token was issued in the future: " + idClaims.getIssueTime());
      }

    }

    // check audience
    if (idClaims.getAudience() == null) {

      throw new AuthenticationServiceException("Id token audience is null");

    } else if (!idClaims.getAudience().contains(config.clientConfig.getClientId())) {

      throw new AuthenticationServiceException("Audience does not match, expected "
          + config.clientConfig.getClientId() + " got " + idClaims.getAudience());
    }

    // compare the nonce to our stored claim
    String nonce;

    try {
      nonce = idClaims.getStringClaim("nonce");
    } catch (ParseException e) {
      throw new AuthenticationServiceException("nonce claim parse error : " + e.getMessage());
    }

    if (Strings.isNullOrEmpty(nonce)) {

      logger.error("ID token did not contain a nonce claim.");

      throw new AuthenticationServiceException("ID token did not contain a nonce claim.");
    }

    String storedNonce = getStoredNonce(session);

    if (!nonce.equals(storedNonce)) {
      logger.error("Possible replay attack detected! The comparison of the nonce in the returned "
          + "ID Token to the session " + NONCE_SESSION_VARIABLE + " failed. Expected " + storedNonce
          + " got " + nonce + ".");

      throw new AuthenticationServiceException(
          "Possible replay attack detected! The comparison of the nonce in the returned "
              + "ID Token to the session " + NONCE_SESSION_VARIABLE + " failed. Expected "
              + storedNonce + " got " + nonce + ".");
    }
  }

  @Override
  public int getTimeSkewAllowance() {

    return timeSkewAllowance;
  }

  @Override
  public void setTimeSkewAllowance(int timeSkewAllowance) {

    this.timeSkewAllowance = timeSkewAllowance;
  }


  public void setTokenRequestor(OidcTokenRequestor tokenRequestor) {
    this.tokenRequestor = tokenRequestor;
  }


}
