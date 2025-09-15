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
package it.infn.mw.iam.core.web.federation;

import java.net.URI;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.trust.TrustChain;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import it.infn.mw.iam.api.client.registration.service.ClientRegistrationService;
import it.infn.mw.iam.api.common.client.AuthorizationGrantType;
import it.infn.mw.iam.api.common.client.OAuthResponseType;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.api.common.client.TokenEndpointAuthenticationMethod;
import it.infn.mw.iam.core.oidc.InvalidTrustChainException;
import it.infn.mw.iam.core.oidc.TrustChainService;

@RestController
@Profile("openid-federation")
public class FederationRegistrationController {

  @Value("${iam.issuer}")
  private String issuer;

  private final TrustChainService trustChainService;
  private final ClientRegistrationService clientRegistrationService;
  private final FederationResponseBuilder federationResponseBuilder;

  public FederationRegistrationController(TrustChainService trustChainService,
      ClientRegistrationService clientRegistrationService,
      FederationResponseBuilder federationResponseBuilder) {
    this.trustChainService = trustChainService;
    this.clientRegistrationService = clientRegistrationService;
    this.federationResponseBuilder = federationResponseBuilder;
  }

  private RegisteredClientDTO createClientDtoFromRpMetadata(EntityStatement rpRequest) {
    RegisteredClientDTO dtoClient = new RegisteredClientDTO();
    OIDCClientMetadata metadata = rpRequest.getClaimsSet().getRPMetadata();
    // Client name
    dtoClient.setClientName(metadata.getName());
    // Contacts
    if (metadata.getEmailContacts() != null) {
      dtoClient.setContacts(new HashSet<>(metadata.getEmailContacts()));
    }
    // Grant types
    if (metadata.getGrantTypes() != null) {
      dtoClient.setGrantTypes(metadata.getGrantTypes()
        .stream()
        .map(GrantType::getValue)
        .map(AuthorizationGrantType::fromGrantType)
        .collect(Collectors.toSet()));
    } else {
      dtoClient.setGrantTypes(Set.of(AuthorizationGrantType.CODE));
    }
    // Redirect Uris
    dtoClient.setRedirectUris(
        metadata.getRedirectionURIs().stream().map(URI::toString).collect(Collectors.toSet()));
    // Response types
    if (metadata.getResponseTypes() != null) {
      dtoClient.setResponseTypes(metadata.getResponseTypes()
        .stream()
        .map(ResponseType::toString)
        .map(OAuthResponseType::fromResponseType)
        .collect(Collectors.toSet()));
    }
    // Token endpoint auth method
    dtoClient.setTokenEndpointAuthMethod(TokenEndpointAuthenticationMethod.client_secret_basic);
    // Logo / Client URI
    if (metadata.getLogoURI() != null) {
      dtoClient.setClientUri(metadata.getLogoURI().toString());
    }
    // Scopes
    if (metadata.getScope() != null) {
      dtoClient.setScope(Set.of(metadata.getScope().toString()));
    } else {
      dtoClient.setScope(Set.of("openid"));
    }

    return dtoClient;
  }

  @PostMapping(value = "/iam/openid-federation/client-registration",
      consumes = "application/entity-statement+jwt",
      produces = "application/explicit-registration-response+jwt")
  public ResponseEntity<String> register(@RequestBody String requestJwt)
      throws ParseException, BadJOSEException, JOSEException, java.text.ParseException {

    // 1. Parse request Entity Statement (self-signed EC of the RP)
    EntityStatement rpRequest = EntityStatement.parse(requestJwt);

    // 2. Verify that aud == issuer (OP)
    if (!issuer.equals(rpRequest.getClaimsSet().getAudience().get(0).getValue())) {
      throw new InvalidTrustChainException("invalid_request", "Invalid audience");
    }

    // 3. Resolve and validate trust chain starting from received EC
    TrustChain trustChain = trustChainService.validateFromEntityConfiguration(rpRequest);

    // 4. Create RegisteredClientDTO from RP metadata
    RegisteredClientDTO dtoClient = createClientDtoFromRpMetadata(rpRequest);
    Date clientExpiration = trustChain.resolveExpirationTime();
    dtoClient
      .setExpiration(LocalDate.ofInstant(clientExpiration.toInstant(), ZoneId.systemDefault()));

    // 5. Register the client by using the already existing service
    RegisteredClientDTO registeredClient =
        clientRegistrationService.registerClient(dtoClient, null, true);

    // 6. Build the response (Entity Statement)
    String responseEs = federationResponseBuilder.build(registeredClient, trustChain);

    return ResponseEntity.ok()
      .contentType(MediaType.valueOf("application/explicit-registration-response+jwt"))
      .body(responseEs);
  }
}
