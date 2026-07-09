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

import java.text.ParseException;
import java.time.Clock;
import java.util.Optional;

import org.springframework.security.authentication.AuthenticationServiceException;

import com.nimbusds.jose.JOSEException;

import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.api.openid_federation.FederatedOpRegistrationService;
import it.infn.mw.iam.config.oidc.OidcClient;
import it.infn.mw.iam.config.oidc.OidcProviderProperties;
import it.infn.mw.iam.core.oidc.FederationException;
import it.infn.mw.iam.persistence.model.IamFederatedClientEntity;
import it.infn.mw.iam.persistence.repository.IamFederatedClientRepository;

public class OpenIdFederationClientConfigurationService extends DefaultClientConfigurationService {

  private final Clock clock;
  private final IamFederatedClientRepository clientRepo;
  private final FederatedOpRegistrationService federationRegistrationService;

  public OpenIdFederationClientConfigurationService(OidcProviderProperties oidcProperties,
      Clock clock, IamFederatedClientRepository clientRepo,
      FederatedOpRegistrationService federationRegistrationService) {
    super(oidcProperties);
    this.clock = clock;
    this.clientRepo = clientRepo;
    this.federationRegistrationService = federationRegistrationService;
  }

  @Override
  public Optional<OidcClient> getClientConfiguration(String issuer) {

    Optional<OidcClient> clientConfig = super.getClientConfiguration(issuer);
    if (clientConfig.isPresent()) {
      return clientConfig;
    }
    Optional<IamFederatedClientEntity> client = clientRepo.findByEntityId(issuer);
    if (client.isPresent()) {
      if (clock.instant().isBefore(client.get().getExpiration().toInstant())) {
        return Optional.of(toOidcClient(client.get()));
      }
    }
    try {
      RegisteredClientDTO registered = federationRegistrationService.registerOp(issuer, client);
      return Optional.of(toOidcClient(registered));

    } catch (JOSEException | ParseException | FederationException e) {
      throw new AuthenticationServiceException("Unable to register federated OP: " + issuer, e);
    }
  }

  private OidcClient toOidcClient(IamFederatedClientEntity client) {
    return new OidcClient(client.getClientId(), client.getClientSecret(),
        client.getRedirectUris().iterator().next(), String.join(" ", client.getScope()), null, null,
        null);
  }

  private OidcClient toOidcClient(RegisteredClientDTO client) {
    return new OidcClient(client.getClientId(), client.getClientSecret(),
        client.getRedirectUris().iterator().next(), String.join(" ", client.getScope()), null, null,
        null);
  }
}
