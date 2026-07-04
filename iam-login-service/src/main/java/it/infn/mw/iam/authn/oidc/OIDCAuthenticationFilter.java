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

import static it.infn.mw.iam.authn.util.JwtUtils.jsonStringSanityChecks;
import static it.infn.mw.iam.authn.util.JwtUtils.parseClaims;
import static it.infn.mw.iam.authn.util.JwtUtils.parseToken;
import static it.infn.mw.iam.authn.util.SessionUtils.NONCE_SESSION_VARIABLE;
import static it.infn.mw.iam.authn.util.SessionUtils.createCodeVerifier;
import static it.infn.mw.iam.authn.util.SessionUtils.createNonce;
import static it.infn.mw.iam.authn.util.SessionUtils.createState;
import static it.infn.mw.iam.authn.util.SessionUtils.getStoredCodeVerifier;
import static it.infn.mw.iam.authn.util.SessionUtils.getStoredNonce;
import static it.infn.mw.iam.authn.util.SessionUtils.getStoredSessionString;
import static it.infn.mw.iam.authn.util.SessionUtils.validateState;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.time.Clock;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mitre.jwt.signer.service.impl.JWKSetCacheService;
import org.mitre.oauth2.model.PKCEAlgorithm;
import org.mitre.openid.connect.client.model.IssuerServiceResponse;
import org.mitre.openid.connect.client.service.IssuerService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Strings;
import com.google.gson.JsonObject;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.authn.oidc.service.OIDCProviderMetadataService;
import it.infn.mw.iam.config.oidc.OidcClient;
import it.infn.mw.iam.config.oidc.OidcProvider;
import it.infn.mw.iam.config.oidc.OidcProviderProperties;

@SuppressWarnings("deprecation")
public class OIDCAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

  public static final Logger LOG = LoggerFactory.getLogger(OIDCAuthenticationFilter.class);

  protected static final String REDIRECT_URI_SESSION_VARIABLE = "redirect_uri";
  protected static final String ISSUER_SESSION_VARIABLE = "issuer";
  protected static final String TARGET_SESSION_VARIABLE = "target";
  protected static final String ACR_SESSION_VARIABLE = "acr_values";
  protected static final String ID_TOKEN_VARIABLE = "id_token";
  protected static final String FILTER_PROCESSES_URL = "/openid_connect_login";

  private JWKSetCacheService validationServices;
  private IssuerService issuerService;
  private OIDCProviderMetadataService servers;
  private OidcProviderProperties clients;
  private PlainAuthRequestUrlBuilder authRequestBuilder;
  private Clock clock;
  private OidcTokenRequestor tokenRequestor;
  private Environment env;
  private ObjectMapper objectMapper;
  private int timeSkewAllowance;

  public OIDCAuthenticationFilter(JWKSetCacheService validationServices,
      IssuerService issuerService, OIDCProviderMetadataService servers,
      OidcProviderProperties clients, PlainAuthRequestUrlBuilder authRequestBuilder, Clock clock,
      OidcTokenRequestor tokenRequestor, Environment env, ObjectMapper objectMapper,
      int timeSkewAllowance) {

    super(FILTER_PROCESSES_URL);
    this.validationServices = validationServices;
    this.issuerService = issuerService;
    this.servers = servers;
    this.clients = clients;
    this.authRequestBuilder = authRequestBuilder;
    this.clock = clock;
    this.tokenRequestor = tokenRequestor;
    this.env = env;
    this.objectMapper = objectMapper;
    this.timeSkewAllowance = timeSkewAllowance;
  }

  @Override
  public void afterPropertiesSet() {
    super.afterPropertiesSet();

    if (validationServices == null) {
      validationServices = new JWKSetCacheService();
    }
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request,
      HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

    if (!Strings.isNullOrEmpty(request.getParameter("error"))) {

      handleError(request, response);
      return null;

    } else if (!Strings.isNullOrEmpty(request.getParameter("code"))) {

      return handleAuthorizationCodeResponse(request);

    } else {

      handleAuthorizationRequest(request, response);
      return null;
    }

  }

  private void handleAuthorizationRequest(HttpServletRequest request, HttpServletResponse response)
      throws IOException {

    HttpSession session = request.getSession();
    IssuerServiceResponse issResp = issuerService.getIssuer(request);

    if (issResp == null) {
      LOG.error("Null issuer response returned from service.");
      throw new AuthenticationServiceException("No issuer found.");
    }

    if (issResp.shouldRedirect()) {
      response.sendRedirect(issResp.getRedirectUrl());
      return;
    }

    String issuer = getValidIssuerFromRequest(session, issResp);
    OIDCProviderMetadata serverConfig = getOidcProviderMetadata(issuer);
    OidcProvider clientConfig = getMatchedOidcProvider(issuer);
    session.setAttribute(ISSUER_SESSION_VARIABLE, serverConfig.issuer());

    String redirectUri = determineRedirectUri(clientConfig, request);
    session.setAttribute(REDIRECT_URI_SESSION_VARIABLE, redirectUri);

    String nonce = createNonce(session);
    String state = createState(session);

    Map<String, String> options = new HashMap<>();

    populateAcrOptions(session, request, options);
    addPkceChallenge(session, clientConfig.getClient().codeChallengeMethod(), options);

    String authRequest = authRequestBuilder.buildAuthRequestUrl(serverConfig, clientConfig,
        redirectUri, nonce, state, options, issResp.getLoginHint());

    LOG.debug("Auth Request: {}", authRequest);

    response.sendRedirect(authRequest);
  }

  protected Authentication handleAuthorizationCodeResponse(HttpServletRequest request) {

    validateState(request);

    String issuer = getIssuerFromSession(request);
    OidcProvider clientConfig = getMatchedOidcProvider(issuer);
    OIDCProviderMetadata metadata = getOidcProviderMetadata(issuer);

    String tokenResponseString = null;

    try {
      tokenResponseString = tokenRequestor.requestTokens(metadata.tokenEndpoint(),
          clientConfig.getClient(), initTokenRequestParameters(request));

    } catch (OidcClientError e) {
      throw new OidcClientError(String.format("Error executing token request against endpoint %s",
          metadata.tokenEndpoint()), e);
    }

    LOG.debug("Token Endpoint returned string: {}", tokenResponseString);

    JsonObject tokenResponse = jsonStringSanityChecks(tokenResponseString);

    String accessTokenValue = null;
    String idTokenValue = null;

    if (tokenResponse.has("access_token")) {
      accessTokenValue = tokenResponse.get("access_token").getAsString();
    } else {
      throw new AuthenticationServiceException(String.format(
          "Token Endpoint did not return an access_token. Response: %s", tokenResponseString));
    }

    if (tokenResponse.has(ID_TOKEN_VARIABLE)) {
      idTokenValue = tokenResponse.get(ID_TOKEN_VARIABLE).getAsString();
    } else {
      logger.error("Token Endpoint did not return an id_token");
      throw new AuthenticationServiceException("Token Endpoint did not return an id_token");
    }

    JWT idToken = parseToken(idTokenValue);
    JWTClaimsSet idClaims = parseClaims(idToken);

    validateSignature(idToken, metadata, clientConfig);
    validateClaims(idClaims, metadata.issuer(), clientConfig.getClient().clientId());
    validateNonceSession(request.getSession(), idClaims);

    PendingOIDCAuthenticationToken oidcToken = new PendingOIDCAuthenticationToken(
        idClaims.getSubject(), idClaims.getIssuer(), metadata, idToken, accessTokenValue);

    return getAuthenticationManager().authenticate(oidcToken);

  }

  protected void handleError(HttpServletRequest request, HttpServletResponse response)
      throws IOException {

    throw new OidcClientError("External authentication error", request.getParameter("error"),
        request.getParameter("error_description"), request.getParameter("error_uri"));
  }

  private OidcProvider getMatchedOidcProvider(String issuer) {

    return clients.getProviders()
      .stream()
      .filter(c -> c.getIssuer().equals(issuer))
      .findFirst()
      .orElseThrow(() -> new AuthenticationServiceException(
          String.format("No client configuration found for issuer: %s", issuer)));
  }

  public MultiValueMap<String, String> initTokenRequestParameters(HttpServletRequest request) {

    MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
    form.add("grant_type", "authorization_code");
    form.add("code", request.getParameter("code"));

    HttpSession session = request.getSession();
    String codeVerifier = getStoredCodeVerifier(session);
    if (codeVerifier != null) {
      form.add("code_verifier", codeVerifier);
    }

    String redirectUri = getStoredSessionString(session, REDIRECT_URI_SESSION_VARIABLE);

    if (redirectUri != null) {
      form.add(REDIRECT_URI_SESSION_VARIABLE, redirectUri);
    }

    return form;

  }

  protected void validateSignature(JWT idToken, OIDCProviderMetadata metadata,
      OidcProvider clientConfig) {

    Algorithm tokenAlg = idToken.getHeader().getAlgorithm();
    OidcClient client = clientConfig.getClient();

    validateAlgorithmMatch(tokenAlg, client.idTokenSignedResponseAlg());
    handlePlainJwt(idToken, tokenAlg);

    if (idToken instanceof SignedJWT signedIdToken) {


      if (tokenAlg.equals(JWSAlgorithm.HS256) || tokenAlg.equals(JWSAlgorithm.HS384)
          || tokenAlg.equals(JWSAlgorithm.HS512)) {

        throw new UnsupportedOperationException(
            String.format("Symmetric ID token signing agorithm %s is not supported", tokenAlg));
      }

      JWTSigningAndValidationService jwtValidator =
          validationServices.getValidator(metadata.jwksUri());

      if (jwtValidator == null) {
        throw new AuthenticationServiceException(
            "Unable to find an appropriate signature validator for ID Token.");
      }

      if (!jwtValidator.validateSignature(signedIdToken)) {
        throw new AuthenticationServiceException("ID Token signature validation failed");
      }
    }

  }

  protected void validateClaims(JWTClaimsSet idClaims, String expectedIssuer, String clientId) {

    String tokenIssuer = idClaims.getIssuer();
    if (tokenIssuer == null) {
      throw new AuthenticationServiceException("Id Token Issuer is null");
    }

    if (!tokenIssuer.equals(expectedIssuer)) {
      throw new AuthenticationServiceException(
          String.format("Issuers do not match, expected %s got %s", expectedIssuer, tokenIssuer));
    }

    Date expiration = idClaims.getExpirationTime();
    if (expiration == null) {
      throw new AuthenticationServiceException("Id Token does not have required expiration claim");
    }

    Date skewedMin = Date.from(clock.instant().minusMillis(timeSkewAllowance * 1000L));
    Date skewedMax = Date.from(clock.instant().plusMillis(timeSkewAllowance * 1000L));

    if (skewedMin.after(expiration)) {
      throw new AuthenticationServiceException(
          String.format("Id Token is expired: %s", expiration));
    }

    Date notBefore = idClaims.getNotBeforeTime();
    if (notBefore != null) {

      Date skewedNbf = Date.from(clock.instant().plusMillis(timeSkewAllowance * 1000L));

      if (skewedNbf.before(notBefore)) {
        throw new AuthenticationServiceException(
            String.format("Id Token not valid until: %s", notBefore));
      }
    }

    Date issuedAt = idClaims.getIssueTime();
    if (issuedAt == null) {
      throw new AuthenticationServiceException("Id Token does not have required issued-at claim");
    }

    if (skewedMax.before(issuedAt)) {
      throw new AuthenticationServiceException(
          String.format("Id Token was issued in the future: %s", issuedAt));
    }

    List<String> aud = idClaims.getAudience();
    if (aud == null) {
      throw new AuthenticationServiceException("Id token audience is null");
    }

    if (!aud.contains(clientId)) {
      throw new AuthenticationServiceException(
          String.format("Audience does not match, expected %s got %s", clientId, aud));
    }
  }

  private void validateNonceSession(HttpSession session, JWTClaimsSet idClaims) {
    String nonce;
    try {
      nonce = idClaims.getStringClaim("nonce");
    } catch (ParseException e) {
      throw new AuthenticationServiceException(
          String.format("nonce claim parse error: %s", e.getMessage()));
    }

    if (Strings.isNullOrEmpty(nonce)) {
      logger.error("ID token did not contain a nonce claim.");
      throw new AuthenticationServiceException("ID token did not contain a nonce claim.");
    }

    String storedNonce = getStoredNonce(session);

    if (!nonce.equals(storedNonce)) {
      throw new AuthenticationServiceException(String.format(
          "Possible replay attack detected! The comparison of the nonce in the returned "
              + "ID Token to the session %s failed. Expected %s got %s.",
          NONCE_SESSION_VARIABLE, storedNonce, nonce));
    }
  }

  private String getValidIssuerFromRequest(HttpSession session, IssuerServiceResponse issResp) {

    if (!Strings.isNullOrEmpty(issResp.getTargetLinkUri())) {
      session.setAttribute(TARGET_SESSION_VARIABLE, issResp.getTargetLinkUri());
    }

    String issuer = issResp.getIssuer();

    if (Strings.isNullOrEmpty(issuer)) {
      LOG.error("No issuer found: {}", issuer);
      throw new AuthenticationServiceException(String.format("No issuer found: %s", issuer));
    }
    return issuer;
  }

  private String getIssuerFromSession(HttpServletRequest request) {

    String issuer = getStoredSessionString(request.getSession(), ISSUER_SESSION_VARIABLE);

    if (issuer == null) {
      throw new AuthenticationServiceException("Issuer not found in session.");
    }
    return issuer;
  }

  private OIDCProviderMetadata getOidcProviderMetadata(String issuer) {

    OIDCProviderMetadata metadata = servers.load(issuer);

    if (metadata == null) {
      LOG.error("No server configuration found for issuer: {}", issuer);
      throw new AuthenticationServiceException(
          String.format("No server configuration found for issuer: %s", issuer));
    }
    return metadata;
  }

  private String determineRedirectUri(OidcProvider clientConfig, HttpServletRequest request) {

    String redirectUri = clientConfig.getClient().redirectUris();

    if (redirectUri == null || !redirectUri.equals(request.getRequestURL().toString())) {
      throw new AuthenticationServiceException(
          String.format("RequestURI mismatch. Expected %s got %s", redirectUri,
              request.getRequestURL().toString()));
    }

    return redirectUri;
  }

  public void populateAcrOptions(HttpSession session, HttpServletRequest request,
      Map<String, String> options) throws JsonProcessingException {

    if (request.getParameter(ACR_SESSION_VARIABLE) != null) {
      options.put(ACR_SESSION_VARIABLE, request.getParameter(ACR_SESSION_VARIABLE));
    } else if (request.getParameter("claims") != null) {
      JsonNode claimsNode = objectMapper.readTree(request.getParameter("claims"));
      JsonNode acrNodeValues = claimsNode.path(ID_TOKEN_VARIABLE).path("acr").path("values");

      if (acrNodeValues.isArray() && acrNodeValues.size() > 0) {
        String acrValues = StreamSupport.stream(acrNodeValues.spliterator(), false)
          .map(JsonNode::asText)
          .collect(Collectors.joining(" "));
        session.setAttribute(ACR_SESSION_VARIABLE, acrValues);
        options.put(ACR_SESSION_VARIABLE, acrValues);
      }

    } else {
      if (Arrays.asList(env.getActiveProfiles()).contains("mfa")) {
        options.put(ACR_SESSION_VARIABLE, "https://refeds.org/profile/mfa");
      }
    }
  }

  public void addPkceChallenge(HttpSession session, String codeChallengeMethod,
      Map<String, String> options) {

    if (codeChallengeMethod != null) {

      String codeVerifier = createCodeVerifier(session);
      options.put("code_challenge_method", codeChallengeMethod);

      // OAuth2.1 states the only PKCE algorithm allowed is S256
      // (restricted also in Spring Authorization Server)
      if (!codeChallengeMethod.equals(PKCEAlgorithm.S256.getName())) {
        throw new AuthenticationServiceException(String
          .format("PKCE algorithm not supported. Expected S256 got %s", codeChallengeMethod));
      }

      try {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        String hash =
            Base64URL.encode(digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII)))
              .toString();
        options.put("code_challenge", hash);
      } catch (NoSuchAlgorithmException e) {
        throw new IllegalStateException("SHA-256 algorithm not available", e);
      }

    }
  }

  private void validateAlgorithmMatch(Algorithm tokenAlg, String clientAlg) {

    if (clientAlg != null && !clientAlg.equals(tokenAlg.toString())) {
      throw new AuthenticationServiceException(String
        .format("Token algorithm %s does not match expected algorithm %s", tokenAlg, clientAlg));
    }

  }

  private void handlePlainJwt(JWT idToken, Algorithm clientAlg) {
    if (!(idToken instanceof PlainJWT)) {
      return;
    }

    if (clientAlg == null) {
      throw new AuthenticationServiceException(
          "Unsigned ID tokens can only be used if explicitly configured in client.");
    }
  }

}
