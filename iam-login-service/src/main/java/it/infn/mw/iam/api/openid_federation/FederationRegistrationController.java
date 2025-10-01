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
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.trust.InvalidEntityMetadataException;
import com.nimbusds.openid.connect.sdk.federation.trust.TrustChain;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import it.infn.mw.iam.api.client.registration.service.ClientRegistrationService;
import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.api.common.client.AuthorizationGrantType;
import it.infn.mw.iam.api.common.client.OAuthResponseType;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.api.common.client.TokenEndpointAuthenticationMethod;
import it.infn.mw.iam.core.oidc.FederationError;
import it.infn.mw.iam.core.oidc.InvalidTrustChainException;
import it.infn.mw.iam.core.oidc.TrustChainService;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;

@RestController
@Profile("openid-federation")
public class FederationRegistrationController {

  @Value("${iam.issuer}")
  private String issuer;

  private final TrustChainService trustChainService;
  private final ClientRegistrationService clientRegistrationService;
  private final FederationResponseBuilder federationResponseBuilder;
  private final IamClientRepository clientRepo;
  private final ClientService clientService;

  public FederationRegistrationController(TrustChainService trustChainService,
      ClientRegistrationService clientRegistrationService,
      FederationResponseBuilder federationResponseBuilder, IamClientRepository clientRepo,
      ClientService clientService) {
    this.trustChainService = trustChainService;
    this.clientRegistrationService = clientRegistrationService;
    this.federationResponseBuilder = federationResponseBuilder;
    this.clientRepo = clientRepo;
    this.clientService = clientService;
  }

  private RegisteredClientDTO createClientDtoFromRpMetadata(EntityStatement rpRequest)
      throws InvalidEntityMetadataException {
    RegisteredClientDTO dtoClient = new RegisteredClientDTO();
    OIDCClientMetadata metadata = rpRequest.getClaimsSet().getRPMetadata();
    if (metadata.getName() != null) {
      dtoClient.setClientName(metadata.getName());
    } else {
      dtoClient.setClientName("OIDFed client");
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
    if (metadata.getRedirectionURIs() == null || metadata.getRedirectionURIs().isEmpty()) {
      throw new InvalidEntityMetadataException("Missing redirect uris from RP Entity Statement");
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
      dtoClient.setTokenEndpointAuthMethod(TokenEndpointAuthenticationMethod.client_secret_basic);
    }
    if (metadata.getScope() != null) {
      dtoClient.setScope(metadata.getScope().toStringList().stream().collect(Collectors.toSet()));
    } else {
      dtoClient.setScope(Set.of("openid"));
    }
    if (rpRequest.getEntityID() == null) {
      throw new InvalidEntityMetadataException("Missing RP Entity ID");
    }
    dtoClient.setEntityId(rpRequest.getEntityID().getValue());

    return dtoClient;
  }

  @PostMapping(value = "/iam/api/oid-fed/client-registration",
      consumes = "application/entity-statement+jwt",
      produces = "application/explicit-registration-response+jwt")
  public ResponseEntity<String> register(@RequestBody String requestJwt)
      throws ParseException, JOSEException, InvalidEntityMetadataException {

    // 1. Parse request Entity Statement (self-signed EC of the RP)
    EntityStatement rpRequest;
    try {
      rpRequest = EntityStatement.parse(requestJwt);
    } catch (com.nimbusds.oauth2.sdk.ParseException e) {
      throw (ParseException) e.getCause();
    }

    Optional<ClientDetailsEntity> existingClient =
        clientRepo.findByEntityId(rpRequest.getEntityID().getValue());

    // 2. Verify that aud == issuer (OP)
    if (!issuer.equals(rpRequest.getClaimsSet().getAudience().get(0).getValue())) {
      throw new InvalidTrustChainException("invalid_request", "Invalid audience");
    }

    // 3. Resolve and validate trust chain starting from received EC
    TrustChain trustChain = trustChainService.validateFromEntityConfiguration(rpRequest);

    // 4. Create RegisteredClientDTO from RP metadata
    RegisteredClientDTO dtoClient = createClientDtoFromRpMetadata(rpRequest);
    dtoClient.setExpiration(trustChain.resolveExpirationTime());

    // 5. Register the client by using the already existing service
    RegisteredClientDTO registeredClient =
        clientRegistrationService.registerClient(dtoClient, null);

    // 6. Build the response (Entity Statement)
    String jwt = federationResponseBuilder.build(registeredClient, trustChain);

    // 7. Invalidate previous client if present
    if (existingClient.isPresent()) {
      clientService.deleteClient(existingClient.get());
    }

    return ResponseEntity.ok()
      .contentType(MediaType.valueOf("application/explicit-registration-response+jwt"))
      .body(jwt);
  }

  @ResponseStatus(HttpStatus.BAD_REQUEST)
  @ExceptionHandler({ParseException.class, InvalidEntityMetadataException.class})
  public ErrorDTO badRequestError(Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }

  @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
  @ExceptionHandler(JOSEException.class)
  public ErrorDTO internalServerError(Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }

  @ResponseStatus(HttpStatus.BAD_REQUEST)
  @ExceptionHandler(InvalidTrustChainException.class)
  public FederationError handleTrustChainException(InvalidTrustChainException e) {
    return new FederationError(e.getErrorCode(), e.getMessage());
  }
}
