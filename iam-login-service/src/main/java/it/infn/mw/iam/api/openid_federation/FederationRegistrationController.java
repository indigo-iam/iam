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

import static it.infn.mw.iam.core.oidc.FederationException.invalidRequest;

import java.text.ParseException;
import java.util.Optional;

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
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.trust.TrustChain;

import it.infn.mw.iam.api.client.registration.service.ClientRegistrationService;
import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.core.oidc.ExplicitClientRegistrationMapper;
import it.infn.mw.iam.core.oidc.FederationError;
import it.infn.mw.iam.core.oidc.FederationException;
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
  private final ExplicitClientRegistrationMapper clientMapper;

  public FederationRegistrationController(TrustChainService trustChainService,
      ClientRegistrationService clientRegistrationService,
      FederationResponseBuilder federationResponseBuilder, IamClientRepository clientRepo,
      ClientService clientService, ExplicitClientRegistrationMapper clientMapper) {
    this.trustChainService = trustChainService;
    this.clientRegistrationService = clientRegistrationService;
    this.federationResponseBuilder = federationResponseBuilder;
    this.clientRepo = clientRepo;
    this.clientService = clientService;
    this.clientMapper = clientMapper;
  }

  @PostMapping(value = "/iam/api/oid-fed/client-registration",
      consumes = "application/entity-statement+jwt",
      produces = "application/explicit-registration-response+jwt")
  public ResponseEntity<String> register(@RequestBody String requestJwt)
      throws FederationException, ParseException, JOSEException {

    // 1. Parse request Entity Statement (self-signed EC of the RP)
    EntityStatement rpRequest;
    try {
      rpRequest = EntityStatement.parse(requestJwt);
    } catch (com.nimbusds.oauth2.sdk.ParseException e) {
      throw invalidRequest(e.getMessage());
    }

    Optional<ClientDetailsEntity> existingClient =
        clientRepo.findByEntityId(rpRequest.getEntityID().getValue());

    // 2. Verify that aud == issuer (OP)
    if (!issuer.equals(rpRequest.getClaimsSet().getAudience().get(0).getValue())) {
      throw invalidRequest("Invalid audience");
    }

    // 3. Resolve and validate trust chain starting from received EC
    TrustChain trustChain = trustChainService.validateFromEntityConfiguration(rpRequest);

    // 4. Create RegisteredClientDTO from RP metadata
    RegisteredClientDTO dtoClient = clientMapper.createClientDtoFromRpMetadata(rpRequest);
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
  @ExceptionHandler(ParseException.class)
  public ErrorDTO badRequestError(Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }

  @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
  @ExceptionHandler(JOSEException.class)
  public ErrorDTO internalServerError(Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }

  @ResponseStatus(HttpStatus.BAD_REQUEST)
  @ExceptionHandler(FederationException.class)
  public FederationError handleFederationExceptions(FederationException e) {
    return new FederationError(e.getErrorCode(), e.getMessage());
  }
}
