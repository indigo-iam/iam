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

import java.net.URI;
import java.text.ParseException;
import java.util.List;
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
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.trust.TrustChain;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

import it.infn.mw.iam.api.client.registration.service.ClientRegistrationService;
import it.infn.mw.iam.api.common.client.AuthorizationGrantType;
import it.infn.mw.iam.api.common.client.OAuthResponseType;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.api.common.client.TokenEndpointAuthenticationMethod;
import it.infn.mw.iam.config.oidc.OpenidFederationProperties;
import it.infn.mw.iam.core.oidc.ExplicitRegistrationEntityStatementBuilder;
import it.infn.mw.iam.core.oidc.InvalidClientMetadataException;
import it.infn.mw.iam.core.oidc.TrustChainService;

@Service
@Profile("openid-federation")
public class FederatedOpRegistrationService {

  public static final Logger LOG = LoggerFactory.getLogger(FederatedOpRegistrationService.class);

  private final TrustChainService tcService;
  private final ExplicitRegistrationEntityStatementBuilder explRegistrationEsBuilder;
  private final ClientRegistrationService clientRegistrationService;
  private final OpenidFederationProperties oidFedProperties;
  private final RestTemplate restTemplate;

  @Value("${iam.baseUrl}")
  private String iamBaseUrl;

  public FederatedOpRegistrationService(TrustChainService tcService,
      ExplicitRegistrationEntityStatementBuilder explRegistrationEsBuilder,
      ClientRegistrationService clientRegistrationService,
      OpenidFederationProperties oidFedProperties) {

    this.tcService = tcService;
    this.explRegistrationEsBuilder = explRegistrationEsBuilder;
    this.clientRegistrationService = clientRegistrationService;
    this.oidFedProperties = oidFedProperties;
    this.restTemplate = new RestTemplate();
  }

  public RegisteredClientDTO registerOp(String issuer) throws JOSEException, ParseException {

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
    SignedJWT signedResponse = SignedJWT.parse(responseJwt);

    // 6. Persist client
    RegisteredClientDTO dtoClient = createClientDtoFromOpMetadata(opEc);
    dtoClient.setExpiration(trustChain.resolveExpirationTime());
    dtoClient.setRequestObjectSigningAlgorithm(signedResponse.getHeader().getAlgorithm());

    return clientRegistrationService.registerClient(dtoClient, null);
  }

  private List<String> selectAuthorityHints(TrustChain trustChain, String issuer) {

    List<String> chainIssuers = trustChain.getSuperiorStatements()
      .stream()
      .map(es -> es.getClaimsSet().getIssuer().getValue())
      .distinct()
      .toList();

    List<String> configuredHints = oidFedProperties.getEntityConfiguration().getAuthorityHints();

    List<String> selected = chainIssuers.stream().filter(configuredHints::contains).toList();

    if (selected.isEmpty()) {
      throw new IllegalStateException("No valid authority_hints found for OP " + issuer);
    }

    return selected;
  }

  private String postRegistration(URI endpoint, String jwt) {

    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(new MediaType("application", "entity-statement+jwt"));

    HttpEntity<String> entity = new HttpEntity<>(jwt, headers);

    try {
      return restTemplate.postForObject(endpoint, entity, String.class);
    } catch (HttpClientErrorException e) {
      throw new AuthenticationServiceException(
          "Federation registration failed: " + e.getResponseBodyAsString(), e);
    }
  }

  private void validateIssuer(String issuer) {
    URI uri = URI.create(issuer);
    if (!"https".equalsIgnoreCase(uri.getScheme())) {
      throw new IllegalArgumentException("Issuer must use https");
    }
  }

  private RegisteredClientDTO createClientDtoFromOpMetadata(EntityStatement opEc) {
    RegisteredClientDTO dtoClient = new RegisteredClientDTO();
    OIDCProviderMetadata metadata = opEc.getClaimsSet().getOPMetadata();

    dtoClient.setClientName("OIDFed OP client");
    Set<AuthorizationGrantType> grantTypes = Optional.ofNullable(metadata.getGrantTypes())
      .orElse(List.of(GrantType.AUTHORIZATION_CODE))
      .stream()
      .map(GrantType::getValue)
      .map(AuthorizationGrantType::fromGrantType)
      .collect(Collectors.toSet());

    dtoClient.setGrantTypes(grantTypes);
    dtoClient.setRedirectUris(Set.of(iamBaseUrl + "/openid_connect_login"));
    Set<String> supportedResponseTypes =
        Set.of(ResponseType.CODE.toString(), ResponseType.TOKEN.toString());
    if (metadata.getResponseTypes() != null) {
      Set<OAuthResponseType> responseTypes = metadata.getResponseTypes()
        .stream()
        .map(ResponseType::toString)
        .filter(supportedResponseTypes::contains)
        .map(OAuthResponseType::fromResponseType)
        .collect(Collectors.toSet());
      if (responseTypes.isEmpty()) {
        throw new InvalidClientMetadataException("invalid_client_metadata",
            "Unsupported response type");
      }
      dtoClient.setResponseTypes(responseTypes);
    } else {
      dtoClient.setResponseTypes(Set.of(OAuthResponseType.CODE));
    }
    dtoClient.setTokenEndpointAuthMethod(TokenEndpointAuthenticationMethod.client_secret_basic);
    if (metadata.getScopes() != null) {
      dtoClient.setScope(metadata.getScopes().toStringList().stream().collect(Collectors.toSet()));
    } else {
      dtoClient.setScope(Set.of("openid"));
    }
    dtoClient.setEntityId(opEc.getEntityID().getValue());
    Optional.ofNullable(metadata.getJWKSetURI())
      .ifPresent(uri -> dtoClient.setJwksUri(uri.toASCIIString()));

    LOG.debug("Client metadata mapped successfully for OP: {}", dtoClient.getEntityId());
    return dtoClient;
  }
}
