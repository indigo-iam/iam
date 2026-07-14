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
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
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

import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mitre.jwt.signer.service.impl.JWKSetCacheService;
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
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;

import it.infn.mw.iam.authn.oidc.service.OIDCProviderMetadataService;
import it.infn.mw.iam.authn.util.JwtUtils;
import it.infn.mw.iam.authn.util.SessionUtils;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.oidc.OidcClient;
import it.infn.mw.iam.core.client.IssuerService;
import it.infn.mw.iam.core.client.IssuerServiceResponse;

public class OIDCAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

  public static final Logger LOG = LoggerFactory.getLogger(OIDCAuthenticationFilter.class);

  protected static final String REDIRECT_URI_SESSION_VARIABLE = "redirect_uri";
  protected static final String ISSUER_SESSION_VARIABLE = "issuer";
  protected static final String TARGET_SESSION_VARIABLE = "target";
  protected static final String ACR_SESSION_VARIABLE = "acr_values";
  protected static final String ID_TOKEN_VARIABLE = "id_token";
  protected static final String FILTER_PROCESSES_URL = "/openid_connect_login";

  private final IamProperties properties;
  private final JWKSetCacheService validationServices;
  private final IssuerService issuerService;
  private final OIDCProviderMetadataService servers;
  private final ClientConfigurationService clientConfigurationService;
  private final PlainAuthRequestUrlBuilder authRequestBuilder;
  private final Clock clock;
  private final OidcTokenRequestor tokenRequestor;
  private final Environment env;
  private final ObjectMapper objectMapper;
  private final int timeSkewAllowance;

  public OIDCAuthenticationFilter(IamProperties properties, JWKSetCacheService validationServices,
      IssuerService issuerService, OIDCProviderMetadataService servers,
      ClientConfigurationService clientConfigurationService,
      PlainAuthRequestUrlBuilder authRequestBuilder, Clock clock, OidcTokenRequestor tokenRequestor,
      Environment env, ObjectMapper objectMapper, int timeSkewAllowance) {

    super(FILTER_PROCESSES_URL);
    this.properties = properties;
    this.validationServices = validationServices;
    this.issuerService = issuerService;
    this.servers = servers;
    this.clientConfigurationService = clientConfigurationService;
    this.authRequestBuilder = authRequestBuilder;
    this.clock = clock;
    this.tokenRequestor = tokenRequestor;
    this.env = env;
    this.objectMapper = objectMapper;
    this.timeSkewAllowance = timeSkewAllowance;
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request,
      HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

    if (!Strings.isNullOrEmpty(request.getParameter("error"))) {
      throw new OidcClientError("External authentication error", request.getParameter("error"),
          request.getParameter("error_description"), request.getParameter("error_uri"));

    }
    if (!Strings.isNullOrEmpty(request.getParameter("code"))) {
      return handleAuthorizationCodeResponse(request);
    }
    handleAuthorizationRequest(request, response);
    return null;
  }

  private void handleAuthorizationRequest(HttpServletRequest request, HttpServletResponse response)
      throws IOException {

    HttpSession session = request.getSession();
    IssuerServiceResponse issResp = issuerService.getIssuer(request);

    if (issResp == null) {
      throw new AuthenticationServiceException("Null issuer response returned from service.");
    }

    if (issResp.shouldRedirect()) {
      response.sendRedirect(issResp.redirectUrl());
      return;
    }

    String issuer = getValidIssuerFromRequest(session, issResp);
    OIDCProviderMetadata serverConfig = getOidcProviderMetadata(issuer);
    OidcClient clientConfig = clientConfigurationService.getClientConfiguration(issuer)
      .orElseThrow(() -> new AuthenticationServiceException(
          String.format("No client configuration found for issuer: %s", issuer)));
    session.setAttribute(ISSUER_SESSION_VARIABLE, serverConfig.issuer());

    String redirectUri =
        properties.getBaseUrl().endsWith("/") ? properties.getBaseUrl() + "openid_connect_login"
            : properties.getBaseUrl() + "/openid_connect_login";
    session.setAttribute(REDIRECT_URI_SESSION_VARIABLE, redirectUri);

    String nonce = SessionUtils.createNonce(session);
    String state = SessionUtils.createState(session);

    Map<String, String> options = new HashMap<>();

    populateAcrOptions(session, request, options);
    addPkceChallenge(session, clientConfig.codeChallengeMethod(), options);

    String authRequest = authRequestBuilder.buildAuthRequestUrl(serverConfig, clientConfig,
        redirectUri, nonce, state, options, issResp.loginHint());

    LOG.debug("Auth Request: {}", authRequest);

    response.sendRedirect(authRequest);
  }

  public Authentication handleAuthorizationCodeResponse(HttpServletRequest request) {

    SessionUtils.validateState(request);

    String issuer = getIssuerFromSession(request);
    OidcClient clientConfig = clientConfigurationService.getClientConfiguration(issuer)
      .orElseThrow(() -> new AuthenticationServiceException(
          String.format("No client configuration found for issuer: %s", issuer)));
    OIDCProviderMetadata metadata = getOidcProviderMetadata(issuer);

    String tokenResponseString = null;

    try {
      tokenResponseString = tokenRequestor.requestTokens(metadata.tokenEndpoint(), clientConfig,
          initTokenRequestParameters(request));

    } catch (OidcClientError e) {
      throw new OidcClientError(String.format("Error executing token request against endpoint %s",
          metadata.tokenEndpoint()), e);
    }

    LOG.debug("Token Endpoint returned string: {}", tokenResponseString);

    JsonObject tokenResponse = JwtUtils.jsonStringSanityChecks(tokenResponseString);

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
      throw new AuthenticationServiceException("Token Endpoint did not return an id_token");
    }

    JWT idToken = JwtUtils.parseToken(idTokenValue);
    JWTClaimsSet idClaims = JwtUtils.parseClaims(idToken);

    Date skewedMin = Date.from(clock.instant().minusMillis(timeSkewAllowance * 1000L));
    Date skewedMax = Date.from(clock.instant().plusMillis(timeSkewAllowance * 1000L));
    JWTSigningAndValidationService jwtValidator =
        validationServices.getValidator(metadata.jwksUri());

    JwtUtils.validateSignature(idToken, clientConfig.idTokenSignedResponseAlg(), jwtValidator);
    JwtUtils.validateClaims(idClaims, metadata.issuer(), clientConfig.clientId(), skewedMin,
        skewedMax);

    SessionUtils.validateNonceSession(request.getSession(), idClaims);

    PendingOIDCAuthenticationToken oidcToken = new PendingOIDCAuthenticationToken(
        idClaims.getSubject(), idClaims.getIssuer(), metadata, idToken, accessTokenValue);

    return getAuthenticationManager().authenticate(oidcToken);

  }

  private OIDCProviderMetadata getOidcProviderMetadata(String issuer) {

    OIDCProviderMetadata metadata = servers.load(issuer);

    if (metadata == null) {
      throw new AuthenticationServiceException(
          String.format("No server configuration found for issuer: %s", issuer));
    }
    return metadata;
  }

  public MultiValueMap<String, String> initTokenRequestParameters(HttpServletRequest request) {

    MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
    form.add("grant_type", "authorization_code");
    form.add("code", request.getParameter("code"));

    HttpSession session = request.getSession();
    String codeVerifier = SessionUtils.getStoredCodeVerifier(session);
    if (codeVerifier != null) {
      form.add("code_verifier", codeVerifier);
    }

    String redirectUri =
        SessionUtils.getStoredSessionString(session, REDIRECT_URI_SESSION_VARIABLE);

    if (redirectUri != null) {
      form.add(REDIRECT_URI_SESSION_VARIABLE, redirectUri);
    }

    return form;

  }

  private String getValidIssuerFromRequest(HttpSession session, IssuerServiceResponse issResp) {

    if (!Strings.isNullOrEmpty(issResp.targetLinkUri())) {
      session.setAttribute(TARGET_SESSION_VARIABLE, issResp.targetLinkUri());
    }

    String issuer = issResp.issuer();

    if (Strings.isNullOrEmpty(issuer)) {
      LOG.error("No issuer found: {}", issuer);
      throw new AuthenticationServiceException(String.format("No issuer found: %s", issuer));
    }
    return issuer;
  }

  private String getIssuerFromSession(HttpServletRequest request) {

    String issuer =
        SessionUtils.getStoredSessionString(request.getSession(), ISSUER_SESSION_VARIABLE);

    if (issuer == null) {
      throw new AuthenticationServiceException("Issuer not found in session.");
    }
    return issuer;
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

    if (codeChallengeMethod == null) {
      return;
    }
    if (!"S256".equalsIgnoreCase(codeChallengeMethod)) {
      throw new AuthenticationServiceException(
          String.format("PKCE algorithm not supported. Expected S256 got %s", codeChallengeMethod));
    }
    String codeVerifier = SessionUtils.createCodeVerifier(session);
    options.put("code_challenge_method", "S256");

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
