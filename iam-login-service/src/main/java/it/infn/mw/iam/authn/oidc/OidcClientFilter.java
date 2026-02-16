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

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Strings;
import com.google.common.collect.Iterables;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.authn.oidc.configuration.ClientConfigurationService;
import it.infn.mw.iam.authn.oidc.configuration.ServerConfigurationService;
import it.infn.mw.iam.authn.oidc.model.PendingOIDCAuthenticationToken;
import it.infn.mw.iam.authn.oidc.model.ServerConfiguration;
import it.infn.mw.iam.authn.util.SessionUtils;
import it.infn.mw.iam.core.jwt.JwkSetCacheService;
import it.infn.mw.iam.core.jwt.JwtSigningAndValidationService;
import it.infn.mw.iam.core.jwt.SymmetricKeyJWTValidatorCacheService;
import it.infn.mw.iam.core.oidc.service.IssuerService;
import it.infn.mw.iam.core.oidc.service.IssuerServiceResponse;
import it.infn.mw.iam.persistence.model.PKCEAlgorithm;

@SuppressWarnings("deprecation")
public class OidcClientFilter extends AbstractAuthenticationProcessingFilter {

  public final static String FILTER_PROCESSES_URL = "/openid_connect_login";

  protected final static String ACR_SESSION_VARIABLE = "acr_values";
  protected final static String CODE_VERIFIER_SESSION_VARIABLE = "code_verifier";
  protected final static String ISSUER_SESSION_VARIABLE = "issuer";
  protected final static String NONCE_SESSION_VARIABLE = "nonce";
  protected final static String REDIRECT_URI_SESSION_VARIABLE = "redirect_uri";
  protected final static String STATE_SESSION_VARIABLE = "state";
  protected final static String TARGET_SESSION_VARIABLE = "target";

  public static final Logger LOG = LoggerFactory.getLogger(OidcClientFilter.class);

  private final ServerConfigurationService servers;
  private final ClientConfigurationService clients;
  private final SymmetricKeyJWTValidatorCacheService symmetricCacheService;
  private final JwkSetCacheService validationServices;
  private final OidcTokenRequestor tokenRequestor;
  private final IssuerService issuerService;
  private final AuthRequestUrlBuilder authRequestBuilder;
  private final Environment env;
  private final int timeSkewAllowance = 300;

  public OidcClientFilter(AuthenticationManager authenticationManager, ServerConfigurationService servers, ClientConfigurationService clients,
      SymmetricKeyJWTValidatorCacheService symmetricCacheService,
      JwkSetCacheService validationServices, OidcTokenRequestor tokenRequestor,
      IssuerService issuerService, AuthRequestUrlBuilder authRequestBuilder, Environment env) {

    super(FILTER_PROCESSES_URL, authenticationManager);
    this.servers = servers;
    this.clients = clients;
    this.symmetricCacheService = symmetricCacheService;
    this.validationServices = validationServices;
    this.issuerService = issuerService;
    this.authRequestBuilder = authRequestBuilder;
    this.tokenRequestor = tokenRequestor;
    this.env = env;
  }

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

  protected static String createNonce(HttpSession session) {

    String nonce = new BigInteger(50, new SecureRandom()).toString(16);
    session.setAttribute(NONCE_SESSION_VARIABLE, nonce);
    return nonce;
  }

  protected static String getStoredNonce(HttpSession session) {

    return SessionUtils.getStoredSessionString(session, NONCE_SESSION_VARIABLE);
  }

  protected static String createState(HttpSession session) {

    String state = new BigInteger(50, new SecureRandom()).toString(16);
    session.setAttribute(STATE_SESSION_VARIABLE, state);
    return state;
  }

  protected static String getStoredState(HttpSession session) {

    return SessionUtils.getStoredSessionString(session, STATE_SESSION_VARIABLE);
  }

  protected static String createCodeVerifier(HttpSession session) {
    String challenge = new BigInteger(50, new SecureRandom()).toString(16);
    session.setAttribute(CODE_VERIFIER_SESSION_VARIABLE, challenge);
    return challenge;
  }

  protected static String getStoredCodeVerifier(HttpSession session) {
    return SessionUtils.getStoredSessionString(session, CODE_VERIFIER_SESSION_VARIABLE);
  }

  public ServerConfigurationService getServerConfigurationService() {
    return servers;
  }

  protected OidcProviderConfiguration lookupProvider(HttpServletRequest request) {

    String issuer =
        SessionUtils.getStoredSessionString(request.getSession(), ISSUER_SESSION_VARIABLE);
    if (issuer == null) {
      throw new AuthenticationServiceException("Issuer not found in session.");
    }
    ServerConfiguration serverConfig =
        getServerConfigurationService().getServerConfiguration(issuer);

    if (serverConfig == null) {
      throw new AuthenticationServiceException("Unknow OpenID provider :" + issuer);
    }

    RegisteredClient clientConfig = clients.getClientConfiguration(serverConfig.getIssuer());

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

    String redirectUri = SessionUtils.getStoredSessionString(request.getSession(), "redirect_uri");

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

  protected void handleError(HttpServletRequest request, HttpServletResponse response)
      throws IOException {

    throw new OidcClientError("External authentication error", request.getParameter("error"),
        request.getParameter("error_description"), request.getParameter("error_uri"));
  }

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
          config.getServerConfig().getTokenEndpointUri(), e.getMessage(), e);
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
            config.getServerConfig(), idToken, accessTokenValue, refreshTokenValue);

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

    Algorithm clientAlg = config.getClientConfig().getIdTokenSignedResponseAlg();

    JwtSigningAndValidationService jwtValidator = null;

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
            this.symmetricCacheService.getSymmetricValidator(config.getClientConfig().getClient());
      } else {
        // otherwise load from the server's public key
        jwtValidator = validationServices.getValidator(config.getServerConfig().getJwksUri());
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

    } else if (!idClaims.getIssuer().equals(config.getServerConfig().getIssuer())) {
      throw new AuthenticationServiceException("Issuers do not match, expected "
          + config.getServerConfig().getIssuer() + " got " + idClaims.getIssuer());
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

    } else if (!idClaims.getAudience().contains(config.getClientConfig().getClientId())) {

      throw new AuthenticationServiceException("Audience does not match, expected "
          + config.getClientConfig().getClientId() + " got " + idClaims.getAudience());
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

  public int getTimeSkewAllowance() {

    return timeSkewAllowance;
  }

  // public void setTimeSkewAllowance(int timeSkewAllowance) {
  //
  // this.timeSkewAllowance = timeSkewAllowance;
  // }
  //
  //
  // public void setTokenRequestor(OidcTokenRequestor tokenRequestor) {
  // this.tokenRequestor = tokenRequestor;
  // }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request,
      HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

    if (!Strings.isNullOrEmpty(request.getParameter("error"))) {

      handleError(request, response);
      return null;
    }
    if (!Strings.isNullOrEmpty(request.getParameter("code"))) {

      Authentication auth = handleAuthorizationCodeResponse(request, response);
      return auth;
    }

    handleAuthorizationRequest(request, response);
    return null;
  }

  protected void handleAuthorizationRequest(HttpServletRequest request,
      HttpServletResponse response) throws IOException {

    HttpSession session = request.getSession();

    IssuerServiceResponse issResp = issuerService.getIssuer(request);

    if (issResp == null) {
      logger.error("Null issuer response returned from service.");
      throw new AuthenticationServiceException("No issuer found.");
    }

    if (issResp.shouldRedirect()) {
      response.sendRedirect(issResp.getRedirectUrl());
    } else {
      String issuer = issResp.getIssuer();

      if (!Strings.isNullOrEmpty(issResp.getTargetLinkUri())) {
        // there's a target URL in the response, we should save this so we can forward to it later
        session.setAttribute(TARGET_SESSION_VARIABLE, issResp.getTargetLinkUri());
      }

      if (Strings.isNullOrEmpty(issuer)) {
        logger.error("No issuer found: " + issuer);
        throw new AuthenticationServiceException("No issuer found: " + issuer);
      }

      ServerConfiguration serverConfig = servers.getServerConfiguration(issuer);
      if (serverConfig == null) {
        logger.error("No server configuration found for issuer: " + issuer);
        throw new AuthenticationServiceException(
            "No server configuration found for issuer: " + issuer);
      }


      session.setAttribute(ISSUER_SESSION_VARIABLE, serverConfig.getIssuer());

      RegisteredClient clientConfig = clients.getClientConfiguration(serverConfig.getIssuer());
      if (clientConfig == null) {
        logger.error("No client configuration found for issuer: " + issuer);
        throw new AuthenticationServiceException(
            "No client configuration found for issuer: " + issuer);
      }

      String redirectUri = null;
      if (clientConfig.getRegisteredRedirectUri() != null
          && clientConfig.getRegisteredRedirectUri().size() == 1) {
        // if there's a redirect uri configured (and only one), use that
        redirectUri = Iterables.getOnlyElement(clientConfig.getRegisteredRedirectUri());
      } else {
        // otherwise our redirect URI is this current URL, with no query parameters
        redirectUri = request.getRequestURL().toString();
      }
      session.setAttribute(REDIRECT_URI_SESSION_VARIABLE, redirectUri);

      // this value comes back in the id token and is checked there
      String nonce = createNonce(session);

      // this value comes back in the auth code response
      String state = createState(session);

      // Map<String, String> options = authOptions.getOptions(serverConfig, clientConfig, request);
      Map<String, String> options = new HashMap<>();

      // if the client requests MFA using claims request parameter, IAM transforms it into the
      // acr_values one
      if (request.getParameter("acr_values") != null) {
        options.put("acr_values", request.getParameter("acr_values"));
      } else if (request.getParameter("claims") != null) {
        JsonNode claimsNode = (new ObjectMapper()).readTree(request.getParameter("claims"));
        JsonNode acrNodeValues = claimsNode.path("id_token").path("acr").path("values");
        if (acrNodeValues.isArray() && acrNodeValues.size() > 0) {
          String acrValues = StreamSupport.stream(acrNodeValues.spliterator(), false)
            .map(JsonNode::asText)
            .collect(Collectors.joining(" "));
          session.setAttribute(ACR_SESSION_VARIABLE, acrValues);
          options.put("acr_values", acrValues);
        }
      } else {
        if (Arrays.asList(env.getActiveProfiles()).contains("mfa")) {
          options.put("acr_values", "https://refeds.org/profile/mfa");
        }
      }

      // if we're using PKCE, handle the challenge here
      if (clientConfig.getCodeChallengeMethod() != null) {
        String codeVerifier = createCodeVerifier(session);
        options.put("code_challenge_method", clientConfig.getCodeChallengeMethod().getName());
        if (clientConfig.getCodeChallengeMethod().equals(PKCEAlgorithm.plain)) {
          options.put("code_challenge", codeVerifier);
        } else if (clientConfig.getCodeChallengeMethod().equals(PKCEAlgorithm.S256)) {
          try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String hash =
                Base64URL.encode(digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII)))
                  .toString();
            options.put("code_challenge", hash);
          } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
          }
        }
      }

      String authRequest = authRequestBuilder.buildAuthRequestUrl(serverConfig, clientConfig,
          redirectUri, nonce, state, options, issResp.getLoginHint());

      logger.debug("Auth Request:  " + authRequest);

      response.sendRedirect(authRequest);
    }
  }

}
