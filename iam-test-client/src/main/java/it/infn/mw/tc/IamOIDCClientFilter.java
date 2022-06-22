package it.infn.mw.tc;

import java.io.IOException;
import java.net.URI;
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
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriUtils;

import com.google.common.base.Strings;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

public class IamOIDCClientFilter extends OIDCAuthenticationFilter {

  private static class OpenIDProviderConfiguration {

    public OpenIDProviderConfiguration(ServerConfiguration sc, RegisteredClient cc) {
      this.serverConfig = sc;
      this.clientConfig = cc;
    }

    ServerConfiguration serverConfig;
    RegisteredClient clientConfig;
  }

  public static final Logger LOG = LoggerFactory.getLogger(IamOIDCClientFilter.class);

  ClientHttpRequestFactory httpRequestFactory;

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

  private RestTemplate basicAuthRequest(RegisteredClient clientConfig) {

    return new RestTemplate(httpRequestFactory) {

      @Override
      protected ClientHttpRequest createRequest(URI url, HttpMethod method) throws IOException {

        ClientHttpRequest httpRequest = super.createRequest(url, method);
        httpRequest.getHeaders().add("Authorization",
            String.format("Basic %s",
                Base64.encode(String.format("%s:%s",
                    UriUtils.encodePathSegment(clientConfig.getClientId(), "UTF-8"),
                    UriUtils.encodePathSegment(clientConfig.getClientSecret(), "UTF-8")))));
        return httpRequest;
      }
    };
  }

  private RestTemplate jwtAuthRequest(RegisteredClient clientConfig) {

    // TO be done
    return null;
  }

  private RestTemplate jwtPrivateKeyAuthRequest(RegisteredClient clientConfig) {

    // TO be done
    return null;
  }

  private RestTemplate formAuthRequest(RegisteredClient clientConfig,
      MultiValueMap<String, String> requestParams) {

    // TO be done
    return null;
  }

  private MultiValueMap<String, String> initTokenRequestParameters(HttpServletRequest request,
      OpenIDProviderConfiguration config) {

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

  private RestTemplate prepareTokenRequest(HttpServletRequest request, RegisteredClient client,
      MultiValueMap<String, String> requestParams) {

    RestTemplate tokenRequest = null;

    switch (client.getTokenEndpointAuthMethod()) {

      case SECRET_BASIC:
        tokenRequest = basicAuthRequest(client);
        break;
      case SECRET_JWT:
        tokenRequest = jwtAuthRequest(client);
        break;
      case PRIVATE_KEY:
        tokenRequest = jwtPrivateKeyAuthRequest(client);
        break;
      case SECRET_POST:
        tokenRequest = formAuthRequest(client, requestParams);
        break;
      case NONE:
        tokenRequest = new RestTemplate(httpRequestFactory);
    }

    if (tokenRequest == null) {
      throw new AuthenticationServiceException("Unsupported token endpoint authentication method");
    }

    return tokenRequest;
  }

  /**
   * Get the named stored session variable as a string. Return null if not found or not a
   * string. @param session @param key @return
   */
  private static String getStoredSessionString(HttpSession session, String key) {

    Object o = session.getAttribute(key);
    if (o != null && o instanceof String) {
      return o.toString();
    } else {
      return null;
    }
  }

  private OpenIDProviderConfiguration lookupProvider(HttpServletRequest request) {

    String issuer = getStoredSessionString(request.getSession(), ISSUER_SESSION_VARIABLE);
    if (issuer == null) {
      throw new AuthenticationServiceException("Issuser not found in session.");
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

    return new OpenIDProviderConfiguration(serverConfig, clientConfig);

  }

  private JsonObject jsonStringSanityChecks(String jsonString) {

    JsonElement jsonRoot = JsonParser.parseString(jsonString);
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

    String error = request.getParameter("error");
    String errorDescription = request.getParameter("error_description");
    String errorURI = request.getParameter("error_uri");

    throw new OidcAuthenticationError("OAuth authentication error: " + errorDescription, error,
        errorDescription, errorURI);

  }

  @Override
  protected Authentication handleAuthorizationCodeResponse(HttpServletRequest request,
      HttpServletResponse response) {

    validateState(request, response);

    OpenIDProviderConfiguration config = lookupProvider(request);

    MultiValueMap<String, String> requestParams = initTokenRequestParameters(request, config);

    RestTemplate tokenRequest = prepareTokenRequest(request, config.clientConfig, requestParams);

    String jsonString = null;

    try {
      jsonString = tokenRequest.postForObject(config.serverConfig.getTokenEndpointUri(),
          requestParams, String.class);
    } catch (RestClientException e) {

      // Handle error
      LOG.error("Token Endpoint error response:  {}", e.getMessage(), e);

      throw new AuthenticationServiceException("Unable to obtain Access Token: " + e.getMessage());
    }

    LOG.debug("Token Endpoint returned string: {}", jsonString);

    JsonObject tokenResponse = jsonStringSanityChecks(jsonString);

    String accessTokenValue = null;
    String idTokenValue = null;
    String refreshTokenValue = null;

    if (tokenResponse.has("access_token")) {
      accessTokenValue = tokenResponse.get("access_token").getAsString();
    } else {
      throw new AuthenticationServiceException(
          "Token Endpoint did not return an access_token: " + jsonString);
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

  private void validateSignature(JWT idToken, OpenIDProviderConfiguration config) {

    Algorithm tokenAlg = idToken.getHeader().getAlgorithm();

    Algorithm clientAlg = config.clientConfig.getIdTokenSignedResponseAlg();

    JWTSigningAndValidationService jwtValidator = null;

    if (clientAlg != null) {
      if (!clientAlg.equals(tokenAlg)) {
        throw new AuthenticationServiceException(
            "Token algorithm " + tokenAlg + " does not match expected algorithm " + clientAlg);
      }
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

  private void validateClaims(HttpSession session, JWT idToken, JWTClaimsSet idClaims,
      OpenIDProviderConfiguration config) {

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


  public ClientHttpRequestFactory getHttpRequestFactory() {

    return httpRequestFactory;
  }

  public void setHttpRequestFactory(ClientHttpRequestFactory httpRequestFactory) {

    this.httpRequestFactory = httpRequestFactory;
  }

  @Override
  public int getTimeSkewAllowance() {

    return timeSkewAllowance;
  }

  @Override
  public void setTimeSkewAllowance(int timeSkewAllowance) {

    this.timeSkewAllowance = timeSkewAllowance;
  }

}
