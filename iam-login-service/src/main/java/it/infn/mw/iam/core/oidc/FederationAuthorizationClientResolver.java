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

import static it.infn.mw.iam.core.oidc.FederationException.invalidTrustChain;
import static org.mitre.openid.connect.request.ConnectRequestParameters.REDIRECT_URI;
import static org.mitre.openid.connect.request.ConnectRequestParameters.STATE;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.servlet.http.HttpServletResponse;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.ClientRelyingPartyEntity.ClientType;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.trust.TrustChain;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import it.infn.mw.iam.api.client.management.service.DefaultClientManagementService;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;

@Component
@Profile("openid-federation")
public class FederationAuthorizationClientResolver implements AuthorizationClientResolver {

  public static final String INVALID_REQUEST_ERROR = "invalid_request";
  public static final String INVALID_CLIENT_METADATA_ERROR = "invalid_client_metadata";
  public static final String INVALID_REQUEST_OBJECT_ERROR = "invalid_request_object";

  private final IamClientRepository clientRepo;
  private final DefaultClientManagementService clientManagementService;
  private final TrustChainService trustChainService;
  private final AutomaticClientRegistrationMapper clientMapper;

  public FederationAuthorizationClientResolver(IamClientRepository clientRepo,
      DefaultClientManagementService clientManagementService, TrustChainService trustChainService,
      AutomaticClientRegistrationMapper clientMapper) {

    this.clientRepo = clientRepo;
    this.clientManagementService = clientManagementService;
    this.trustChainService = trustChainService;
    this.clientMapper = clientMapper;
  }

  @Override
  public Optional<ClientDetailsEntity> resolveClient(String clientId, Map<String, String> params,
      HttpServletResponse response) throws IOException {

    if (clientId == null) {
      return Optional.empty();
    }

    if (!clientId.startsWith("https://")) {
      return clientRepo.findByClientId(clientId);
    }

    if (!validateUrl(clientId, response, params)) {
      return Optional.empty();
    }

    return handleFederationClient(response, params, clientId);
  }

  private boolean validateUrl(String clientId, HttpServletResponse response,
      Map<String, String> params) throws IOException {

    try {

      URL url = new URL(clientId);

      if (!"https".equalsIgnoreCase(url.getProtocol()) || url.getHost() == null
          || url.getHost().isEmpty() || url.getQuery() != null || url.getRef() != null) {

        OAuthError.sendAuthenticationError(response, params.get(REDIRECT_URI), params.get(STATE),
            INVALID_REQUEST_ERROR, "Entity ID URL is not compliant");

        return false;
      }

      return true;

    } catch (MalformedURLException e) {

      OAuthError.sendAuthenticationError(response, params.get(REDIRECT_URI), params.get(STATE),
          INVALID_REQUEST_ERROR, "Malformed Entity ID URL");

      return false;
    }
  }

  private Optional<ClientDetailsEntity> handleFederationClient(HttpServletResponse response,
      Map<String, String> params, String clientId) throws IOException {

    String requestObj = params.get("request");

    if (requestObj == null) {

      OAuthError.sendAuthenticationError(response, params.get(REDIRECT_URI), params.get(STATE),
          INVALID_REQUEST_ERROR, "Missing request object");

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
      dtoClient.setClientType(ClientType.INTERNAL);
      dtoClient.setRequestObjectSigningAlgorithm(jwt.getHeader().getAlgorithm());

      Optional<ClientDetailsEntity> maybeClient = clientRepo.findByClientId(clientId);

      if (maybeClient.isPresent()) {

        clientManagementService.updateClient(clientId, dtoClient);

      } else {

        clientManagementService.saveNewClient(dtoClient);
      }

      return clientRepo.findByClientId(clientId);

    } catch (FederationException e) {

      if (!response.isCommitted()) {
        OAuthError.sendAuthenticationError(response, null, null, e.getErrorCode(), e.getMessage());
      }

    } catch (Exception e) {

      if (!response.isCommitted()) {
        OAuthError.sendAuthenticationError(response, null, null, "server_error", e.getMessage());
      }
    }

    return Optional.empty();
  }

  private TrustChain extractAndValidateTrustChain(JWTClaimsSet claims, String clientId)
      throws FederationException {

    Object trustChainObj = claims.getClaim("trust_chain");

    if (trustChainObj != null) {

      ObjectMapper mapper = new ObjectMapper();

      List<String> trustChainStrings =
          mapper.convertValue(trustChainObj, new TypeReference<List<String>>() {});

      List<EntityStatement> trustChain = new ArrayList<>();

      for (String jwtString : trustChainStrings) {

        EntityStatement entityStatement;

        try {

          entityStatement = EntityStatement.parse(jwtString);

        } catch (com.nimbusds.oauth2.sdk.ParseException e) {

          throw invalidTrustChain(e.getMessage(), e);
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

    OIDCClientMetadata rpMetadata = rpRequest.getClaimsSet().getRPMetadata();

    if (rpMetadata == null) {

      OAuthError.sendAuthenticationError(response, null, null, INVALID_CLIENT_METADATA_ERROR,
          "Missing openid_relying_party metadata");

      return false;
    }

    Optional<JWKSet> jwkSet = loadJwkSet(rpMetadata, response);

    if (jwkSet.isEmpty()) {
      return false;
    }

    for (JWK jwk : jwkSet.get().getKeys()) {

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

      } catch (JOSEException ignored) {
        // ignore exception
      }
    }

    OAuthError.sendAuthenticationError(response, params.get(REDIRECT_URI), params.get(STATE),
        INVALID_REQUEST_OBJECT_ERROR, "Invalid signature on request object");

    return false;
  }

  private Optional<JWKSet> loadJwkSet(OIDCClientMetadata rpMetadata, HttpServletResponse response)
      throws IOException {

    JWKSet jwkSet = rpMetadata.getJWKSet();

    if (jwkSet == null && rpMetadata.getJWKSetURI() != null) {

      try {

        jwkSet = JWKSet.load(rpMetadata.getJWKSetURI().toURL());

      } catch (Exception e) {

        OAuthError.sendAuthenticationError(response, null, null, INVALID_CLIENT_METADATA_ERROR,
            "Unable to fetch JWKS from RP's jwks_uri");

        return Optional.empty();
      }
    }

    if (jwkSet == null) {

      OAuthError.sendAuthenticationError(response, null, null, INVALID_CLIENT_METADATA_ERROR,
          "No JWKS or jwks_uri provided by RP");

      return Optional.empty();
    }

    return Optional.of(jwkSet);
  }
}
