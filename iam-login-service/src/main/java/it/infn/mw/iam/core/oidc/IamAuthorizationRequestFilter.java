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
package it.infn.mw.iam.core.oidc;

import static org.mitre.openid.connect.request.ConnectRequestParameters.CLIENT_ID;
import static org.mitre.openid.connect.request.ConnectRequestParameters.ERROR;
import static org.mitre.openid.connect.request.ConnectRequestParameters.LOGIN_HINT;
import static org.mitre.openid.connect.request.ConnectRequestParameters.LOGIN_REQUIRED;
import static org.mitre.openid.connect.request.ConnectRequestParameters.MAX_AGE;
import static org.mitre.openid.connect.request.ConnectRequestParameters.PROMPT;
import static org.mitre.openid.connect.request.ConnectRequestParameters.PROMPT_LOGIN;
import static org.mitre.openid.connect.request.ConnectRequestParameters.PROMPT_NONE;
import static org.mitre.openid.connect.request.ConnectRequestParameters.PROMPT_SEPARATOR;
import static org.mitre.openid.connect.request.ConnectRequestParameters.REDIRECT_URI;
import static org.mitre.openid.connect.request.ConnectRequestParameters.STATE;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang.StringEscapeUtils;
import org.apache.http.client.utils.URIBuilder;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.openid.connect.service.LoginHintExtracter;
import org.mitre.openid.connect.service.impl.RemoveLoginHintsWithHTTP;
import org.mitre.openid.connect.web.AuthenticationTimeStamper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.endpoint.RedirectResolver;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.trust.TrustChain;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import it.infn.mw.iam.api.client.management.service.DefaultClientManagementService;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;

@SuppressWarnings("deprecation")
@Component("iamAuthzRequestFilter")
public class IamAuthorizationRequestFilter extends GenericFilterBean {

  private static final Logger log = LoggerFactory.getLogger(IamAuthorizationRequestFilter.class);

  public static final String PROMPTED = "PROMPT_FILTER_PROMPTED";
  public static final String PROMPT_REQUESTED = "PROMPT_FILTER_REQUESTED";

  private final Environment env;
  private final IamClientRepository clientRepo;
  private final DefaultClientManagementService clientManagementService;
  private final RedirectResolver redirectResolver;
  private final TrustChainService trustChainService;
  private final AutomaticClientRegistrationMapper clientMapper;

  private LoginHintExtracter loginHintExtracter = new RemoveLoginHintsWithHTTP();
  private RequestMatcher requestMatcher = new AntPathRequestMatcher("/authorize");

  public IamAuthorizationRequestFilter(Environment env, IamClientRepository clientRepo,
      DefaultClientManagementService clientManagementService, RedirectResolver redirectResolver,
      TrustChainService trustChainService, AutomaticClientRegistrationMapper clientMapper) {

    this.env = env;
    this.clientRepo = clientRepo;
    this.clientManagementService = clientManagementService;
    this.redirectResolver = redirectResolver;
    this.trustChainService = trustChainService;
    this.clientMapper = clientMapper;
  }

  @Autowired(required = false)
  public void setLoginHintExtracter(LoginHintExtracter loginHintExtracter) {
    if (loginHintExtracter != null) {
      this.loginHintExtracter = loginHintExtracter;
    }
  }

  @Override
  public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
      throws IOException, ServletException {

    HttpServletRequest request = (HttpServletRequest) req;
    HttpServletResponse response = (HttpServletResponse) res;
    HttpSession session = request.getSession();

    // skip everything that's not an authorize URL
    if (!requestMatcher.matches(request)) {
      chain.doFilter(req, res);
      return;
    }

    Map<String, String> params = createRequestMap(request.getParameterMap());

    Optional<ClientDetailsEntity> client = Optional.empty();

    String clientId = params.get(CLIENT_ID);
    if (clientId != null) {
      boolean federationEnabled =
          Arrays.stream(env.getActiveProfiles()).anyMatch("openid-federation"::equals);
      if (federationEnabled && clientId.startsWith("https://")) {
        if (!validateUrl(clientId, response, params)) {
          return;
        }
        client = handleFederationClient(response, params, clientId);
        if (client.isEmpty()) {
          return;
        }
      } else {
        client = clientRepo.findByClientId(clientId);
        if (client.isEmpty()) {
          sendAuthenticationError(response, null, null, "invalid_client", "Unknown client");
          return;
        }
      }
    }

    handleLoginHint(params, session);

    if (!handlePromptParameter(params, client, session, request, response, chain)) {
      return;
    }

    if (params.get(MAX_AGE) != null
        || (client.isPresent() && client.get().getDefaultMaxAge() != null)) {
      enforceMaxAgeIfNeeded(params, client, session);
    }
    chain.doFilter(req, res);
  }

  private boolean validateUrl(String clientId, HttpServletResponse response,
      Map<String, String> params) throws IOException {
    try {
      URL url = new URL(clientId);
      if (!"https".equalsIgnoreCase(url.getProtocol()) || url.getHost() == null
          || url.getHost().isEmpty() || url.getQuery() != null || url.getRef() != null) {
        sendAuthenticationError(response, params.get(REDIRECT_URI), params.get(STATE),
            "invalid_request", "Entity ID URL is not compliant");
        return false;
      }
      return true;
    } catch (MalformedURLException e) {
      sendAuthenticationError(response, params.get(REDIRECT_URI), params.get(STATE),
          "invalid_request", "Malformed Entity ID URL");
      return false;
    }
  }

  private Optional<ClientDetailsEntity> handleFederationClient(HttpServletResponse response,
      Map<String, String> params, String clientId) throws IOException {
    String requestObj = params.get("request");
    if (requestObj == null) {
      sendAuthenticationError(response, params.get(REDIRECT_URI), params.get(STATE),
          "invalid_request", "Missing request object");
      return Optional.empty();
    }

    try {
      SignedJWT jwt = SignedJWT.parse(requestObj);
      JWTClaimsSet claims = jwt.getJWTClaimsSet();

      TrustChain validTrustChain = extractAndValidateTrustChain(claims, clientId);
      EntityStatement rpRequest = validTrustChain.getLeafSelfStatement();

      if (!verifyRequestObjectSignature(jwt, rpRequest, response, params)) {
        return Optional.empty();
      }

      RegisteredClientDTO dtoClient = clientMapper.createClientDtoFromRpMetadata(rpRequest);
      dtoClient.setExpiration(validTrustChain.resolveExpirationTime());
      dtoClient.setClientId(clientId);
      dtoClient.setRequestObjectSigningAlgorithm(jwt.getHeader().getAlgorithm());

      Optional<ClientDetailsEntity> maybeClient = clientRepo.findByClientId(clientId);
      if (maybeClient.isPresent()) {
        clientManagementService.updateClient(clientId, dtoClient);
      } else {
        clientManagementService.saveNewClient(dtoClient);
      }

      return clientRepo.findByClientId(clientId);

    } catch (InvalidClientMetadataException e) {
      // If we reach here, maybe the response has not been committed yet
      if (!response.isCommitted()) {
        sendAuthenticationError(response, null, null, e.getErrorCode(), e.getMessage());
      }
    } catch (InvalidTrustChainException e) {
      if (!response.isCommitted()) {
        sendAuthenticationError(response, null, null, e.getErrorCode(), e.getMessage());
      }
    } catch (Exception e) {
      log.error("Unexpected federation error", e);
      if (!response.isCommitted()) {
        sendAuthenticationError(response, null, null, "server_error", e.getMessage());
      }
    }
    return Optional.empty();
  }

  private TrustChain extractAndValidateTrustChain(JWTClaimsSet claims, String clientId)
      throws BadJOSEException, JOSEException, ParseException {
    Object trustChainObj = claims.getClaim("trust_chain");
    if (trustChainObj != null) {
      ObjectMapper mapper = new ObjectMapper();
      List<String> trustChainStrings = mapper.convertValue(trustChainObj,
          new com.fasterxml.jackson.core.type.TypeReference<List<String>>() {});
      List<EntityStatement> trustChain = new ArrayList<>();
      for (String jwtString : trustChainStrings) {
        SignedJWT signedJWT = SignedJWT.parse(jwtString);
        EntityStatement entityStatement;
        try {
          entityStatement = EntityStatement.parse(signedJWT);
        } catch (com.nimbusds.oauth2.sdk.ParseException e) {
          throw (ParseException) e.getCause();
        }
        trustChain.add(entityStatement);
      }
      return trustChainService.validateFromProvidedChain(trustChain);
    } else {
      return trustChainService.validateFromEntityId(clientId);
    }
  }

  private boolean verifyRequestObjectSignature(SignedJWT jwt, EntityStatement rpRequest,
      HttpServletResponse response, Map<String, String> params) throws IOException, JOSEException {
    var rpMetadata = rpRequest.getClaimsSet().getRPMetadata();
    if (rpMetadata == null) {
      sendAuthenticationError(response, null, null, "invalid_client_metadata",
          "Missing openid_relying_party metadata");
      return false;
    }
    Optional<JWKSet> jwkSet = loadJwkSet(rpMetadata, response);
    if (jwkSet.isEmpty()) {
      return false;
    }
    for (var jwk : jwkSet.get().getKeys()) {
      try {
        JWSVerifier verifier = switch (jwk.getKeyType().getValue()) {
          case "RSA" -> new RSASSAVerifier((RSAKey) jwk.toPublicJWK());
          case "EC" -> new ECDSAVerifier((ECKey) jwk.toPublicJWK());
          case "OKP" -> new Ed25519Verifier((OctetKeyPair) jwk.toPublicJWK());
          default -> null;
        };
        if (verifier != null && jwt.verify(verifier)) {
          return true;
        }
      } catch (JOSEException e) {
        // Ignored: try the next key in the set
      }
    }
    sendAuthenticationError(response, params.get(REDIRECT_URI), params.get(STATE),
        "invalid_request_object", "Invalid signature on request object");
    return false;
  }

  private Optional<JWKSet> loadJwkSet(OIDCClientMetadata rpMetadata, HttpServletResponse response)
      throws IOException {
    var jwkSet = rpMetadata.getJWKSet();
    if (jwkSet == null && rpMetadata.getJWKSetURI() != null) {
      try {
        var uri = rpMetadata.getJWKSetURI().toURL();
        jwkSet = JWKSet.load(uri);
      } catch (Exception e) {
        sendAuthenticationError(response, null, null, "invalid_client_metadata",
            "Unable to fetch JWKS from RP's jwks_uri");
        return Optional.empty();
      }
    }
    if (jwkSet == null) {
      sendAuthenticationError(response, null, null, "invalid_client_metadata",
          "No JWKS or jwks_uri provided by RP");
      return Optional.empty();
    }
    return Optional.of(jwkSet);
  }

  private void sendAuthenticationError(HttpServletResponse response, String redirectUri,
      String state, String error, String description) throws IOException {
    if (!Strings.isNullOrEmpty(redirectUri)) {
      try {
        URIBuilder uriBuilder = new URIBuilder(redirectUri);
        uriBuilder.addParameter(ERROR, error);
        if (!Strings.isNullOrEmpty(description)) {
          uriBuilder.addParameter("error_description", description);
        }
        if (!Strings.isNullOrEmpty(state)) {
          uriBuilder.addParameter(STATE, state);
        }
        response.sendRedirect(uriBuilder.build().toString());
      } catch (URISyntaxException e) {
        log.error("Can't build redirect URI, sending error instead", e);
        response.sendError(HttpServletResponse.SC_BAD_REQUEST, "invalid_redirect_uri");
      }
    } else {
      // no redirect_uri
      response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
      response.setContentType("text/html;charset=UTF-8");
      response.getWriter()
        .write(
            "<html><head><title>OAuth Error</title></head><body>" + "<h2>Authorization Error</h2>"
                + "<p><strong>error:</strong> " + StringEscapeUtils.escapeHtml(error) + "</p>"
                + "<p><strong>error_description:</strong> "
                + StringEscapeUtils.escapeHtml(description) + "</p>" + "</body></html>");
    }
  }

  private void handleLoginHint(Map<String, String> params, HttpSession session) {
    // save the login hint to the session
    // but first check to see if the login hint makes any sense
    String loginHint = loginHintExtracter.extractHint(params.get(LOGIN_HINT));
    if (!Strings.isNullOrEmpty(loginHint)) {
      session.setAttribute(LOGIN_HINT, loginHint);
    } else {
      session.removeAttribute(LOGIN_HINT);
    }
  }

  private boolean handlePromptParameter(Map<String, String> params,
      Optional<ClientDetailsEntity> client, HttpSession session, HttpServletRequest request,
      HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

    String prompt = params.get(PROMPT);
    if (prompt == null) {
      return true;
    }
    // we have a "prompt" parameter
    List<String> prompts = Splitter.on(PROMPT_SEPARATOR).splitToList(Strings.nullToEmpty(prompt));

    if (prompts.contains(PROMPT_NONE)) {
      // see if the user's logged in
      Authentication auth = SecurityContextHolder.getContext().getAuthentication();
      if (auth != null) {
        // user's been logged in already (by session management)
        // we're OK, continue without prompting
        chain.doFilter(request, response);
        return false;
      }
      log.info("Client requested no prompt");
      // user hasn't been logged in, we need to "return an error"
      if (client.isPresent() && params.get(REDIRECT_URI) != null) {
        // if we've got a redirect URI then we'll send it
        String url = redirectResolver.resolveRedirect(params.get(REDIRECT_URI), client.get());
        sendAuthenticationError(response, url, params.get(STATE), LOGIN_REQUIRED, null);
        return false;
      }
      response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied");
      return false;
    }

    if (prompts.contains(PROMPT_LOGIN)) {
      // first see if the user's already been prompted in this session
      if (session.getAttribute(PROMPTED) == null) {
        // user hasn't been PROMPTED yet, we need to check
        session.setAttribute(PROMPT_REQUESTED, Boolean.TRUE);
        // see if the user's logged in
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null) {
          // user's been logged in already (by session management)
          // log them out and continue
          SecurityContextHolder.getContext().setAuthentication(null);
        }
      } else {
        // user has been PROMPTED, we're fine
        // but first, undo the prompt tag
        session.removeAttribute(PROMPTED);
      }
      chain.doFilter(request, response);
      return false;
    }

    return true;
  }

  private void enforceMaxAgeIfNeeded(Map<String, String> params,
      Optional<ClientDetailsEntity> client, HttpSession session) {
    // default to the client's stored value, check the string parameter
    Integer max = (client.isPresent() ? client.get().getDefaultMaxAge() : null);
    String maxAge = params.get(MAX_AGE);
    if (maxAge != null) {
      max = Integer.parseInt(maxAge);
    }
    if (max != null) {
      Date authTime = (Date) session.getAttribute(AuthenticationTimeStamper.AUTH_TIMESTAMP);
      if (authTime != null) {
        long seconds = (new Date().getTime() - authTime.getTime()) / 1000;
        if (seconds > max) {
          // session is too old, log the user out and continue
          SecurityContextHolder.getContext().setAuthentication(null);
        }
      }
    }
  }

  /**
   * @param parameterMap
   * @return
   */
  private Map<String, String> createRequestMap(Map<String, String[]> parameterMap) {
    Map<String, String> requestMap = new HashMap<>();

    for (Map.Entry<String, String[]> entry : parameterMap.entrySet()) {
      String key = entry.getKey();
      String[] val = entry.getValue();

      if (val != null && val.length > 0) {
        // add the first value only (which is what Spring seems to do)
        requestMap.put(key, val[0]);
      }
    }

    return requestMap;
  }

  /**
   * @return the requestMatcher
   */
  public RequestMatcher getRequestMatcher() {
    return requestMatcher;
  }

  /**
   * @param requestMatcher the requestMatcher to set
   */
  public void setRequestMatcher(RequestMatcher requestMatcher) {
    this.requestMatcher = requestMatcher;
  }
}
