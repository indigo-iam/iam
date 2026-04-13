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

import java.text.ParseException;
import java.time.Clock;
import java.util.Date;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.annotation.Validated;

import it.infn.mw.iam.api.client.management.validation.OnClientCreation;
import it.infn.mw.iam.api.client.service.ClientConverter;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.audit.events.client.FederatedClientCreatedEvent;
import it.infn.mw.iam.audit.events.client.FederatedClientRemovedEvent;
import it.infn.mw.iam.persistence.model.IamFederatedClientEntity;
import it.infn.mw.iam.persistence.repository.IamFederatedClientRepository;

@Service
@Transactional
public class IamFederatedClientService {

  private final Clock clock;
  private final IamFederatedClientRepository iamFedClientsRepo;
  private final ClientConverter clientConverter;
  private final ApplicationEventPublisher eventPublisher;

  public IamFederatedClientService(Clock clock, IamFederatedClientRepository iamFedClientsRepo,
      ClientConverter clientConverter, ApplicationEventPublisher eventPublisher) {
    this.clock = clock;
    this.iamFedClientsRepo = iamFedClientsRepo;
    this.eventPublisher = eventPublisher;
    this.clientConverter = clientConverter;
  }

  @Validated(OnClientCreation.class)
  public RegisteredClientDTO saveClient(RegisteredClientDTO dtoClient) throws ParseException {
    IamFederatedClientEntity client = clientConverter.entityFromFederatedClientRequest(dtoClient);
    client.setCreatedAt(Date.from(clock.instant()));
    client.setActive(true);
    client.setExpiration(dtoClient.getExpiration());
    client.setEntityId(dtoClient.getEntityId());
    iamFedClientsRepo.save(client);
    eventPublisher.publishEvent(new FederatedClientCreatedEvent(this, client));
    return clientConverter.registeredFederatedClientDtoFromEntity(client);
  }

  public void deleteClient(IamFederatedClientEntity client) {
    iamFedClientsRepo.delete(client);
    eventPublisher.publishEvent(new FederatedClientRemovedEvent(this, client));
  }
}
