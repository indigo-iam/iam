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

import java.text.ParseException;
import java.util.Date;
import java.util.Optional;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.RegisteredClient;
import org.mitre.openid.connect.client.service.ClientConfigurationService;
import org.mitre.openid.connect.config.ServerConfiguration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.AuthenticationServiceException;

import com.nimbusds.jose.JOSEException;

import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;

@Profile("openid-federation")
public class FederationClientConfigurationService implements ClientConfigurationService {

  private IamClientRepository clientRepo;
  private FederatedOpRegistrationService federationRegistrationService;

  public FederationClientConfigurationService(IamClientRepository clientRepo,
      FederatedOpRegistrationService federationRegistrationService) {
    this.clientRepo = clientRepo;
    this.federationRegistrationService = federationRegistrationService;
  }

  @Override
  public RegisteredClient getClientConfiguration(ServerConfiguration serverConfig) {

    Optional<ClientDetailsEntity> client = clientRepo.findByEntityId(serverConfig.getIssuer());

    if (client.isPresent()) {
      Date expiration = client.get().getClientRelyingParty().getExpiration();

      if (expiration.after(new Date())) {
        return toRegisteredClient(client.get());
      }
    }

    try {
      RegisteredClientDTO registered =
          federationRegistrationService.registerOp(serverConfig.getIssuer());

      return toRegisteredClient(registered);

    } catch (JOSEException | ParseException e) {
      throw new AuthenticationServiceException(
          "Unable to register federated OP " + serverConfig.getIssuer(), e);
    }
  }

  private RegisteredClient toRegisteredClient(ClientDetailsEntity entity) {
    RegisteredClient rc = new RegisteredClient();
    rc.setClientId(entity.getClientId());
    rc.setClientSecret(entity.getClientSecret());
    rc.setRedirectUris(entity.getRedirectUris());
    rc.setScope(entity.getScope());
    return rc;
  }

  private RegisteredClient toRegisteredClient(RegisteredClientDTO dto) {
    RegisteredClient rc = new RegisteredClient();
    rc.setClientId(dto.getClientId());
    rc.setClientSecret(dto.getClientSecret());
    rc.setRedirectUris(dto.getRedirectUris());
    rc.setScope(dto.getScope());
    return rc;
  }
}
