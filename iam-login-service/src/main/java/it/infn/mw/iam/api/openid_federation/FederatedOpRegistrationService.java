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
package it.infn.mw.iam.api.openid_federation;

import static it.infn.mw.iam.core.oidc.FederationException.invalidClientMetadata;
import static it.infn.mw.iam.core.oidc.FederationException.invalidRedirectUri;
import static it.infn.mw.iam.core.oidc.FederationException.invalidRequest;
import static it.infn.mw.iam.core.oidc.FederationException.invalidTrustChain;

import java.net.URI;
import java.text.ParseException;
import java.time.Clock;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
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
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.trust.TrustChain;

import it.infn.mw.iam.api.common.client.AuthorizationGrantType;
import it.infn.mw.iam.api.common.client.OAuthResponseType;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.api.common.client.TokenEndpointAuthenticationMethod;
import it.infn.mw.iam.authn.oidc.RestTemplateFactory;
import it.infn.mw.iam.config.oidc.OpenidFederationProperties;
import it.infn.mw.iam.core.oidc.ExplicitRegistrationEntityStatementBuilder;
import it.infn.mw.iam.core.oidc.FederationException;
import it.infn.mw.iam.core.oidc.IamFederatedClientService;
import it.infn.mw.iam.core.oidc.TrustAnchorRepository;
import it.infn.mw.iam.core.oidc.TrustChainService;
import it.infn.mw.iam.persistence.model.IamFederatedClientEntity;
import net.minidev.json.JSONObject;

@Service
@Profile("openid-federation")
public class FederatedOpRegistrationService {

  public static final Logger LOG = LoggerFactory.getLogger(FederatedOpRegistrationService.class);

  private final TrustChainService tcService;
  private final ExplicitRegistrationEntityStatementBuilder explRegistrationEsBuilder;
  private final IamFederatedClientService federateClientsService;
  private final OpenidFederationProperties oidFedProperties;
  private final TrustAnchorRepository trustAnchorRepository;
  private final RestTemplate restTemplate;
  private final Clock clock;

  @Value("${iam.baseUrl}")
  private String iamBaseUrl;

  public FederatedOpRegistrationService(TrustChainService tcService,
      ExplicitRegistrationEntityStatementBuilder explRegistrationEsBuilder,
      IamFederatedClientService federateClientsService, OpenidFederationProperties oidFedProperties,
      TrustAnchorRepository trustAnchorRepository, RestTemplateFactory restTemplateFactory,
      Clock clock) {

    this.tcService = tcService;
    this.explRegistrationEsBuilder = explRegistrationEsBuilder;
    this.federateClientsService = federateClientsService;
    this.oidFedProperties = oidFedProperties;
    this.trustAnchorRepository = trustAnchorRepository;
    this.restTemplate = restTemplateFactory.newRestTemplate();
    this.clock = clock;
  }

  public RegisteredClientDTO registerOp(String issuer,
      Optional<IamFederatedClientEntity> existingClient)
      throws JOSEException, ParseException, FederationException {

    validateIssuer(issuer);

    // 1. Resolve trust chain
    TrustChain trustChain = tcService.validateFromEntityId(issuer);

    // 2. Select authority_hints
    List<String> authorityHints = selectAuthorityHints(trustChain, issuer);

    // 3. Build Explicit Registration Entity Statement
    String registrationJwt = explRegistrationEsBuilder.build(issuer, authorityHints);

    // 4. Discover OP federation registration endpoint
    EntityStatement opEc = trustChain.getLeafSelfStatement();
    URI regEndpoint = opEc.getClaimsSet().getOPMetadata().getFederationRegistrationEndpointURI();

    // 5. POST explicit registration request
    String responseJwt = postRegistration(regEndpoint, registrationJwt);

    EntityStatement es = null;
    try {
      es = EntityStatement.parse(responseJwt);
    } catch (com.nimbusds.oauth2.sdk.ParseException e) {
      throw invalidClientMetadata("Failed to parse JWT: " + e);
    }

    // 6. Validate OP response
    validateJwt(es, issuer);
    validateTrustAnchorAndAuthorityHints(authorityHints, es);
    validateSignature(responseJwt, trustChain);

    // 7. Persist client
    RegisteredClientDTO dtoClient =
        createClientDtoFromOpResponse(es.getSignedStatement().getJWTClaimsSet());

    RegisteredClientDTO registeredClient = federateClientsService.saveClient(dtoClient);

    if (existingClient.isPresent()) {
      federateClientsService.deleteClient(existingClient.get());
    }

    return registeredClient;
  }

  private List<String> selectAuthorityHints(TrustChain trustChain, String issuer)
      throws FederationException {

    String commonTA = trustChain.getTrustAnchorEntityID().getValue();

    List<String> configuredHints = oidFedProperties.getEntityConfiguration().getAuthorityHints();
    List<String> selected =
        configuredHints.stream().filter(hint -> leadsToTA(hint, commonTA)).toList();

    if (selected.isEmpty()) {
      throw invalidTrustChain(
          "No authority_hints lead to trust anchor " + commonTA + " for OP: " + issuer);
    }

    return selected;
  }

  private String postRegistration(URI endpoint, String jwt) throws FederationException {

    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(new MediaType("application", "entity-statement+jwt"));

    HttpEntity<String> entity = new HttpEntity<>(jwt, headers);

    try {
      return restTemplate.postForObject(endpoint, entity, String.class);
    } catch (HttpClientErrorException e) {
      throw invalidRequest("Federation registration failed: " + e.getResponseBodyAsString(), e);
    }
  }

  private void validateIssuer(String issuer) throws FederationException {
    URI uri = URI.create(issuer);
    if (!"https".equalsIgnoreCase(uri.getScheme())) {
      throw invalidRequest("Issuer must use https");
    }
  }

  private RegisteredClientDTO createClientDtoFromOpResponse(JWTClaimsSet jwtClaimSet)
      throws FederationException, ParseException {
    RegisteredClientDTO dtoClient = new RegisteredClientDTO();

    JSONObject rpMetadata = extractRpMetadata(jwtClaimSet);

    dtoClient.setClientName(
        Optional.ofNullable(rpMetadata.getAsString("client_name")).orElse("OIDFed remote client"));

    String clientId = rpMetadata.getAsString("client_id");
    dtoClient.setClientId(clientId);

    String clientSecret = rpMetadata.getAsString("client_secret");
    if (clientSecret != null) {
      dtoClient.setClientSecret(clientSecret);
    }

    dtoClient.setTokenEndpointAuthMethod(
        Optional.ofNullable(rpMetadata.getAsString("token_endpoint_auth_method"))
          .map(TokenEndpointAuthenticationMethod::valueOf)
          .orElse(TokenEndpointAuthenticationMethod.client_secret_basic));

    List<String> grantTypesClaim = getStringList(rpMetadata, "grant_types");
    if (grantTypesClaim.isEmpty()) {
      grantTypesClaim = List.of(GrantType.AUTHORIZATION_CODE.getValue());
    }
    Set<AuthorizationGrantType> grantTypes = grantTypesClaim.stream()
      .map(AuthorizationGrantType::fromGrantType)
      .collect(Collectors.toSet());
    dtoClient.setGrantTypes(grantTypes);

    Set<String> supportedResponseTypes =
        Set.of(ResponseType.CODE.toString(), ResponseType.TOKEN.toString());
    List<String> responseTypesClaim = getStringList(rpMetadata, "response_types");
    if (responseTypesClaim.isEmpty()) {
      dtoClient.setResponseTypes(Set.of(OAuthResponseType.CODE));
    } else {
      Set<OAuthResponseType> responseTypes = responseTypesClaim.stream()
        .filter(supportedResponseTypes::contains)
        .map(OAuthResponseType::fromResponseType)
        .collect(Collectors.toSet());
      if (responseTypes.isEmpty()) {
        throw invalidClientMetadata("Unsupported response type");
      }
      dtoClient.setResponseTypes(responseTypes);
    }

    String scope = rpMetadata.getAsString("scope");
    if (scope != null) {
      dtoClient.setScope(Set.of(scope.split(" ")));
    } else {
      dtoClient.setScope(Set.of("openid"));
    }

    String jwksUri = rpMetadata.getAsString("jwks_uri");
    if (jwksUri != null) {
      dtoClient.setJwksUri(jwksUri);
    }
    Object jwksObj = rpMetadata.get("jwks");
    if (jwksObj != null) {
      dtoClient.setJwk(jwksObj.toString());
    }

    List<String> redirectUris = getStringList(rpMetadata, "redirect_uris");
    if (redirectUris == null || redirectUris.isEmpty()) {
      throw invalidRedirectUri("Missing redirect URIs");
    }
    dtoClient.setRedirectUris(Set.copyOf(getStringList(rpMetadata, "redirect_uris")));

    dtoClient.setEntityId(jwtClaimSet.getIssuer());

    dtoClient.setExpiration(jwtClaimSet.getExpirationTime());

    LOG.debug("Client metadata mapped successfully for OP: {}", dtoClient.getEntityId());
    return dtoClient;
  }

  private JSONObject extractRpMetadata(JWTClaimsSet claims)
      throws FederationException, ParseException {
    Map<String, Object> metadataMap = claims.getJSONObjectClaim("metadata");
    JSONObject metadataJson = new JSONObject(metadataMap);

    try {
      return JSONObjectUtils.getJSONObject(metadataJson, "openid_relying_party");
    } catch (com.nimbusds.oauth2.sdk.ParseException e) {
      throw invalidClientMetadata("Invalid or missing openid_relying_party metadata: " + e);
    }
  }

  private List<String> getStringList(JSONObject json, String key) {
    Object value = json.get(key);
    if (value instanceof Collection<?>) {
      return ((Collection<?>) value).stream().map(Object::toString).toList();
    }
    return List.of();
  }

  private boolean leadsToTA(String hint, String trustAnchor) {
    try {
      TrustChain tc = tcService.validateFromEntityId(hint);
      return tc != null && tc.getTrustAnchorEntityID() != null
          && trustAnchor.equals(tc.getTrustAnchorEntityID().getValue());
    } catch (FederationException e) {
      return false;
    }
  }

  private void validateJwt(EntityStatement es, String issuer) throws FederationException {
    Date now = Date.from(clock.instant());
    Date iat = es.getClaimsSet().getIssueTime();
    Date exp = es.getClaimsSet().getExpirationTime();

    if (iat.after(now)) {
      throw invalidClientMetadata("Entity Statement has iat in the future: " + iat);
    }

    if (exp.before(now)) {
      throw invalidClientMetadata("Entity Statement is expired: " + exp);
    }

    if (!es.getClaimsSet().getIssuer().getValue().equals(issuer)) {
      throw invalidClientMetadata("Invalid issuer");
    }

    if (!es.getClaimsSet().getSubject().getValue().equals(iamBaseUrl)) {
      throw invalidClientMetadata("Invalid subject");
    }

    List<Audience> audience = es.getClaimsSet().getAudience();
    if (audience == null || audience.stream().noneMatch(aud -> iamBaseUrl.equals(aud.getValue()))) {
      throw invalidClientMetadata("Invalid audience");
    }
  }

  private void validateTrustAnchorAndAuthorityHints(List<String> authorityHints, EntityStatement es)
      throws FederationException {
    String taId = es.getClaimsSet().getStringClaim("trust_anchor");
    if (!trustAnchorRepository.isTrusted(taId)) {
      throw invalidClientMetadata("No trusted Trust Anchor found: " + taId);
    }

    boolean match = authorityHints.stream().anyMatch(hint -> leadsToTA(hint, taId));
    if (!match) {
      throw invalidClientMetadata("None of the authority_hints leads to the trust anchor: " + taId);
    }
  }

  private void validateSignature(String jwt, TrustChain tc)
      throws ParseException, FederationException, JOSEException {
    SignedJWT signedJwt = SignedJWT.parse(jwt);
    JWSHeader header = signedJwt.getHeader();
    String kid = header.getKeyID();

    EntityStatement immediateSuperior = tc.getSuperiorStatements().get(0);
    JWKSet jwkSet = immediateSuperior.getClaimsSet().getJWKSet();
    JWK jwk = jwkSet.getKeyByKeyId(kid);

    if (jwk == null) {
      throw invalidClientMetadata("Signing key not trusted by federation");
    }

    JWSVerifier verifier;

    if (jwk instanceof RSAKey rsaKey) {
      verifier = new RSASSAVerifier(rsaKey);
    } else if (jwk instanceof ECKey ecKey) {
      verifier = new ECDSAVerifier(ecKey);
    } else if (jwk instanceof OctetKeyPair okpKey) {
      verifier = new Ed25519Verifier(okpKey);
    } else {
      throw invalidClientMetadata("Unsupported key type: " + jwk.getKeyType());
    }

    if (!signedJwt.verify(verifier)) {
      throw invalidClientMetadata("Invalid JWT signature");
    }
  }
}
