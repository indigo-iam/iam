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
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.http.client.utils.URIBuilder;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.service.ClientDetailsEntityService;
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
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.trust.TrustChain;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import it.infn.mw.iam.api.client.management.service.DefaultClientManagementService;
import it.infn.mw.iam.api.common.client.AuthorizationGrantType;
import it.infn.mw.iam.api.common.client.OAuthResponseType;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.api.common.client.TokenEndpointAuthenticationMethod;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;

@SuppressWarnings("deprecation")
@Component("iamAuthzRequestFilter")
public class IamAuthorizationRequestFilter extends GenericFilterBean {

  private static final Logger log = LoggerFactory.getLogger(IamAuthorizationRequestFilter.class);

  public static final String PROMPTED = "PROMPT_FILTER_PROMPTED";
  public static final String PROMPT_REQUESTED = "PROMPT_FILTER_REQUESTED";

  @Autowired
  private Environment env;

  @Autowired
  private ClientDetailsEntityService clientService;

  @Autowired
  private IamClientRepository clientRepo;

  @Autowired
  private DefaultClientManagementService clientManagementService;

  @Autowired
  private RedirectResolver redirectResolver;

  @Autowired
  private TrustChainService trustChainService;

  @Autowired(required = false)
  private LoginHintExtracter loginHintExtracter = new RemoveLoginHintsWithHTTP();

  private RequestMatcher requestMatcher = new AntPathRequestMatcher("/authorize");

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

    ClientDetailsEntity client = null;

    if (params.get(CLIENT_ID) != null) {
      String clientId = params.get(CLIENT_ID);
      if (isOidFedProfile() && isFederationClientId(clientId)) {
        String requestObj = params.get("request");
        if (requestObj != null) {
          try {
            SignedJWT jwt = SignedJWT.parse(requestObj);
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            Object trustChainObj = claims.getClaim("trust_chain");
            TrustChain validTrustChain = null;
            List<EntityStatement> trustChain = new ArrayList<>();
            if (trustChainObj != null) {
              ObjectMapper mapper = new ObjectMapper();
              List<String> trustChainStrings = mapper.convertValue(trustChainObj,
                  new com.fasterxml.jackson.core.type.TypeReference<List<String>>() {});
              for (String jwtString : trustChainStrings) {
                SignedJWT signedJWT = SignedJWT.parse(jwtString);
                EntityStatement entityStatement = EntityStatement.parse(signedJWT);
                trustChain.add(entityStatement);
              }
              validTrustChain = trustChainService.validateFromProvidedChain(trustChain);
            } else {
              validTrustChain = trustChainService.validateFromEntityId(clientId);
            }
            // Build client from metadata
            EntityStatement rpRequest = validTrustChain.getLeafSelfStatement();
            // Verify request JWT's signature
            if (!verifyRequestObjectSignature(jwt, rpRequest, response, params)) {
              return;
            }
            RegisteredClientDTO dtoClient = createClientDtoFromRpMetadata(rpRequest);
            dtoClient.setExpiration(validTrustChain.resolveExpirationTime());
            // Client_id MUST be the RP's entity ID
            dtoClient.setClientId(clientId);
            // Check if client already registered and not expired
            Optional<ClientDetailsEntity> maybeClient = clientRepo.findByClientId(clientId);
            if (maybeClient.isPresent()
                && maybeClient.get().getClientRelyingParty().getExpiration().after(new Date())) {
              clientManagementService.updateClient(clientId, dtoClient);
            } else {
              clientManagementService.saveNewClient(dtoClient);
            }
          } catch (InvalidClientMetadataException e) {
            sendAuthenticationError(response, params.get(REDIRECT_URI), params.get(STATE),
                "invalid_client_metadata", "Invalid RP metadata");
            return;
          } catch (Exception e) {
            sendAuthenticationError(response, params.get(REDIRECT_URI), params.get(STATE),
                "server_error", "Unexpected error during trust chain validation");
            return;
          }
        } else {
          sendAuthenticationError(response, params.get(REDIRECT_URI), params.get(STATE),
              "invalid_request", "Missing request object");
          return;
        }
      }
      client = clientService.loadClientByClientId(clientId);
    }

    // save the login hint to the session
    // but first check to see if the login hint makes any sense
    String loginHint = loginHintExtracter.extractHint(params.get(LOGIN_HINT));
    if (!Strings.isNullOrEmpty(loginHint)) {
      session.setAttribute(LOGIN_HINT, loginHint);
    } else {
      session.removeAttribute(LOGIN_HINT);
    }

    if (params.get(PROMPT) != null) {
      // we have a "prompt" parameter
      String prompt = params.get(PROMPT);
      List<String> prompts = Splitter.on(PROMPT_SEPARATOR).splitToList(Strings.nullToEmpty(prompt));

      if (prompts.contains(PROMPT_NONE)) {
        // see if the user's logged in
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth != null) {
          // user's been logged in already (by session management)
          // we're OK, continue without prompting
          chain.doFilter(req, res);
        } else {
          log.info("Client requested no prompt");
          // user hasn't been logged in, we need to "return an error"
          if (client != null && params.get(REDIRECT_URI) != null) {

            // if we've got a redirect URI then we'll send it
            String url = redirectResolver.resolveRedirect(params.get(REDIRECT_URI), client);

            try {
              URIBuilder uriBuilder = new URIBuilder(url);

              uriBuilder.addParameter(ERROR, LOGIN_REQUIRED);
              if (!Strings.isNullOrEmpty(params.get(STATE))) {
                uriBuilder.addParameter(STATE, params.get(STATE));
              }

              response.sendRedirect(uriBuilder.toString());
              return;

            } catch (URISyntaxException e) {
              log.error("Can't build redirect URI for prompt=none, sending error instead", e);
              response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied");
              return;
            }
          }

          response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied");
        }
      } else if (prompts.contains(PROMPT_LOGIN)) {

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
            chain.doFilter(req, res);
          } else {
            // user hasn't been logged in yet, we can keep going since we'll get there
            chain.doFilter(req, res);
          }
        } else {
          // user has been PROMPTED, we're fine

          // but first, undo the prompt tag
          session.removeAttribute(PROMPTED);
          chain.doFilter(req, res);
        }
      } else {
        // prompt parameter is a value we don't care about, not our business
        chain.doFilter(req, res);
      }

    } else if (params.get(MAX_AGE) != null
        || (client != null && client.getDefaultMaxAge() != null)) {

      // default to the client's stored value, check the string parameter
      Integer max = (client != null ? client.getDefaultMaxAge() : null);
      String maxAge = params.get(MAX_AGE);
      if (maxAge != null) {
        max = Integer.parseInt(maxAge);
      }

      if (max != null) {

        Date authTime = (Date) session.getAttribute(AuthenticationTimeStamper.AUTH_TIMESTAMP);

        Date now = new Date();
        if (authTime != null) {
          long seconds = (now.getTime() - authTime.getTime()) / 1000;
          if (seconds > max) {
            // session is too old, log the user out and continue
            SecurityContextHolder.getContext().setAuthentication(null);
          }
        }
      }
      chain.doFilter(req, res);
    } else {
      // no prompt parameter, not our business
      chain.doFilter(req, res);
    }
  }

  private boolean isOidFedProfile() {
    return Arrays.stream(env.getActiveProfiles()).anyMatch("openid-federation"::equals);
  }

  private boolean isFederationClientId(String clientId) {
    try {
      new URL(clientId);
      return true;
    } catch (MalformedURLException e) {
      return false;
    }
  }

  private boolean verifyRequestObjectSignature(SignedJWT jwt, EntityStatement rpRequest,
      HttpServletResponse response, Map<String, String> params) throws IOException, JOSEException {
    var rpMetadata = rpRequest.getClaimsSet().getRPMetadata();
    if (rpMetadata == null) {
      sendAuthenticationError(response, params.get(REDIRECT_URI), params.get(STATE),
          "invalid_client_metadata", "Missing openid_relying_party metadata");
      return false;
    }
    var jwkSet = rpMetadata.getJWKSet();
    if (jwkSet == null && rpMetadata.getJWKSetURI() != null) {
      try {
        var uri = rpMetadata.getJWKSetURI().toURL();
        jwkSet = JWKSet.load(uri);
      } catch (Exception e) {
        sendAuthenticationError(response, params.get(REDIRECT_URI), params.get(STATE),
            "invalid_client_metadata", "Unable to fetch JWKS from RP's jwks_uri");
        return false;
      }
    }
    if (jwkSet == null) {
      sendAuthenticationError(response, params.get(REDIRECT_URI), params.get(STATE),
          "invalid_client_metadata", "No JWKS or jwks_uri provided by RP");
      return false;
    }
    boolean verified = false;
    for (var jwk : jwkSet.getKeys()) {
      JWSVerifier verifier = switch (jwk.getKeyType().getValue()) {
        case "RSA" -> new RSASSAVerifier((RSAKey) jwk.toPublicJWK());
        case "EC" -> new ECDSAVerifier((ECKey) jwk.toPublicJWK());
        case "OKP" -> new Ed25519Verifier((OctetKeyPair) jwk.toPublicJWK());
        default -> null;
      };
      if (verifier != null) {
        try {
          if (jwt.verify(verifier)) {
            verified = true;
            break;
          }
        } catch (JOSEException e) {
          // Ignored: try the next key in the set
        }
      }
    }
    if (!verified) {
      sendAuthenticationError(response, params.get(REDIRECT_URI), params.get(STATE),
          "invalid_request_object", "Invalid signature on request object");
      return false;
    }
    return true;
  }

  private RegisteredClientDTO createClientDtoFromRpMetadata(EntityStatement rpRequest)
      throws InvalidClientMetadataException {
    RegisteredClientDTO dtoClient = new RegisteredClientDTO();
    OIDCClientMetadata metadata = rpRequest.getClaimsSet().getRPMetadata();
    if (metadata.getName() != null) {
      dtoClient.setClientName(metadata.getName());
    } else {
      dtoClient.setClientName("OIDFed automatic client");
    }
    if (metadata.getEmailContacts() != null) {
      dtoClient.setContacts(new HashSet<>(metadata.getEmailContacts()));
    }
    if (metadata.getGrantTypes() != null) {
      dtoClient.setGrantTypes(metadata.getGrantTypes()
        .stream()
        .map(GrantType::getValue)
        .map(AuthorizationGrantType::fromGrantType)
        .collect(Collectors.toSet()));
    } else {
      dtoClient.setGrantTypes(Set.of(AuthorizationGrantType.CODE));
    }
    if (metadata.getRedirectionURIs() == null) {
      throw new InvalidClientMetadataException("invalid_redirect_uri",
          "Missing redirect uris from RP Entity Statement");
    }
    dtoClient.setRedirectUris(
        metadata.getRedirectionURIs().stream().map(URI::toString).collect(Collectors.toSet()));
    if (metadata.getResponseTypes() != null) {
      dtoClient.setResponseTypes(metadata.getResponseTypes()
        .stream()
        .map(ResponseType::toString)
        .map(OAuthResponseType::fromResponseType)
        .collect(Collectors.toSet()));
    } else {
      dtoClient.setResponseTypes(Set.of(OAuthResponseType.CODE));
    }
    if (metadata.getTokenEndpointAuthMethod() != null) {
      dtoClient.setTokenEndpointAuthMethod(TokenEndpointAuthenticationMethod
        .valueOf(metadata.getTokenEndpointAuthMethod().getValue()));
    } else {
      dtoClient.setTokenEndpointAuthMethod(TokenEndpointAuthenticationMethod.private_key_jwt);
    }
    if (metadata.getJWKSetURI() == null && metadata.getJWKSet() == null) {
      throw new InvalidClientMetadataException("invalid_client_metadata",
          "Missing jwks and jwks_uri");
    }
    if (metadata.getJWKSetURI() != null) {
      dtoClient.setJwksUri(metadata.getJWKSetURI().toASCIIString());
    }
    if (metadata.getJWKSet() != null) {
      dtoClient.setJwk(metadata.getJWKSet().toString());
    }
    if (metadata.getScope() != null) {
      dtoClient.setScope(metadata.getScope().toStringList().stream().collect(Collectors.toSet()));
    } else {
      dtoClient.setScope(Set.of("openid"));
    }
    if (rpRequest.getEntityID() == null) {
      throw new InvalidClientMetadataException("invalid_client_metadata", "Missing RP Entity ID");
    }
    dtoClient.setEntityId(rpRequest.getEntityID().getValue());

    return dtoClient;
  }

  private void sendAuthenticationError(HttpServletResponse response, String redirectUri,
      String state, String error, String description) throws IOException {
    if (redirectUri != null) {
      try {
        URIBuilder uriBuilder = new URIBuilder(redirectUri);
        uriBuilder.addParameter("error", error);
        if (description != null) {
          uriBuilder.addParameter("error_description", description);
        }
        if (state != null) {
          uriBuilder.addParameter("state", state);
        }
        response.sendRedirect(uriBuilder.build().toString());
      } catch (URISyntaxException e) {
        // invalid redirect_uri
        response.sendError(HttpServletResponse.SC_BAD_REQUEST, "invalid_redirect_uri");
      }
    } else {
      // no redirect_uri
      response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
      response.setContentType("application/json");
      response.getWriter()
        .write("{\"error\":\"" + error + "\",\"error_description\":\"" + description + "\"}");
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
