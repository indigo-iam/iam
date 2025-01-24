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
package it.infn.mw.iam.api.client.management.service;

import static it.infn.mw.iam.api.client.util.ClientSuppliers.accountNotFound;
import static it.infn.mw.iam.api.client.util.ClientSuppliers.clientNotFound;
import static it.infn.mw.iam.persistence.model.IamClient.AuthMethod.NONE;
import static java.util.Objects.isNull;

import java.text.ParseException;
import java.time.Clock;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.validation.constraints.NotBlank;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.validation.annotation.Validated;

import it.infn.mw.iam.api.client.management.validation.OnClientCreation;
import it.infn.mw.iam.api.client.management.validation.OnClientUpdate;
import it.infn.mw.iam.api.client.service.ClientConverter;
import it.infn.mw.iam.api.client.service.ClientDefaultsService;
import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.api.client.util.ClientSuppliers;
import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.common.PagingUtils;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.api.scim.converter.UserConverter;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.audit.events.account.client.AccountClientOwnerAssigned;
import it.infn.mw.iam.audit.events.account.client.AccountClientOwnerRemoved;
import it.infn.mw.iam.audit.events.client.ClientRegistrationAccessTokenRotatedEvent;
import it.infn.mw.iam.audit.events.client.ClientRemovedEvent;
import it.infn.mw.iam.audit.events.client.ClientSecretUpdatedEvent;
import it.infn.mw.iam.audit.events.client.ClientStatusChangedEvent;
import it.infn.mw.iam.audit.events.client.ClientUpdatedEvent;
import it.infn.mw.iam.config.client_registration.ClientRegistrationProperties;
import it.infn.mw.iam.core.IamTokenService;
import it.infn.mw.iam.notification.NotificationFactory;
import it.infn.mw.iam.persistence.model.IamAccessToken;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAccountClient;
import it.infn.mw.iam.persistence.model.IamClient;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;

@Service
@Validated
public class DefaultClientManagementService implements ClientManagementService {

  private final Clock clock;
  private final ClientService clientService;
  private final ClientConverter converter;
  private final UserConverter userConverter;
  private final IamAccountRepository accountRepo;
  private final OIDCTokenService oidcTokenService;
  private final IamTokenService tokenService;
  private final IamClientRepository clientRepository;
  private final ApplicationEventPublisher eventPublisher;
  private final NotificationFactory notificationFactory;

  public DefaultClientManagementService(Clock clock, ClientService clientService, ClientRegistrationProperties properties,
      ClientConverter converter, ClientDefaultsService defaultsService, UserConverter userConverter,
      IamAccountRepository accountRepo, OIDCTokenService oidcTokenService,
      IamTokenService tokenService, IamClientRepository clientRepository,
      ApplicationEventPublisher aep, NotificationFactory notificationFactory) {
    this.clock = clock;
    this.clientService = clientService;
    this.converter = converter;
    this.userConverter = userConverter;
    this.accountRepo = accountRepo;
    this.oidcTokenService = oidcTokenService;
    this.tokenService = tokenService;
    this.clientRepository = clientRepository;
    this.eventPublisher = aep;
    this.notificationFactory = notificationFactory;
  }

  @Override
  public ListResponseDTO<RegisteredClientDTO> retrieveAllClients(Pageable pageable) {

    Page<IamClient> pagedResults = clientRepository.findAll(pageable);

    ListResponseDTO.Builder<RegisteredClientDTO> resultBuilder = ListResponseDTO.builder();

    return resultBuilder
      .resources(pagedResults.getContent()
        .stream()
        .map(converter::registeredClientDtoFromEntity)
        .collect(Collectors.toList()))
      .fromPage(pagedResults, pageable)
      .build();
  }

  @Override
  public Optional<RegisteredClientDTO> retrieveClientByClientId(String clientId) {
    return clientRepository.findByClientId(clientId).map(converter::registeredClientDtoFromEntity);
  }

  @Validated(OnClientCreation.class)
  @Override
  public RegisteredClientDTO saveNewClient(RegisteredClientDTO client) throws ParseException {

    IamClient entity = converter.entityFromClientManagementRequest(client);
    entity.setDynamicallyRegistered(false);
    entity.setCreatedAt(Date.from(clock.instant()));
    entity.setActive(true);

    clientService.setupClientDefaults(entity);
    entity = clientRepository.save(entity);

    return converter.registeredClientDtoFromEntity(entity);
  }

  @Override
  public void deleteClientByClientId(String clientId) {

    IamClient client = clientRepository.findByClientId(clientId)
      .orElseThrow(ClientSuppliers.clientNotFound(clientId));

    clientRepository.delete(client);
    eventPublisher.publishEvent(new ClientRemovedEvent(this, client));
  }

  @Override
  public void updateClientStatus(String clientId, boolean status, String userId) {

    IamClient client = clientRepository.findByClientId(clientId)
      .orElseThrow(ClientSuppliers.clientNotFound(clientId));
    client = clientService.updateClientStatus(client, status, userId);
    String message = "Client " + (status ? "enabled" : "disabled");
    eventPublisher.publishEvent(new ClientStatusChangedEvent(this, client, message));
    notificationFactory.createClientStatusChangedMessageFor(client, getClientOwners(clientId));
  }

  private List<IamAccount> getClientOwners(String clientId) {
    return clientService.findClientOwners(clientId, PagingUtils.buildUnpagedPageRequest())
      .getContent()
      .stream()
      .map(IamAccountClient::getAccount)
      .collect(Collectors.toList());
  }

  @Validated(OnClientUpdate.class)
  @Override
  public RegisteredClientDTO updateClient(String clientId, RegisteredClientDTO client)
      throws ParseException {

    IamClient oldClient = clientRepository.findByClientId(clientId)
      .orElseThrow(ClientSuppliers.clientNotFound(clientId));

    IamClient newClient = converter.entityFromClientManagementRequest(client);

    newClient.setId(oldClient.getId());
    newClient.setCreatedAt(oldClient.getCreatedAt());
    newClient.setClientId(oldClient.getClientId());
    newClient.setAuthorities(oldClient.getAuthorities());
    newClient.setDynamicallyRegistered(oldClient.isDynamicallyRegistered());
    newClient.setActive(oldClient.isActive());

    if (NONE.equals(newClient.getTokenEndpointAuthMethod())) {
      newClient.setClientSecret(null);
    } else if (isNull(client.getClientSecret())) {
      client.setClientSecret(clientService.generateClientSecret());
    }

    newClient = clientService.updateClient(newClient);
    eventPublisher.publishEvent(new ClientUpdatedEvent(this, newClient));
    return converter.registeredClientDtoFromEntity(newClient);
  }

  @Override
  public ListResponseDTO<RegisteredClientDTO> retrieveAllDynamicallyRegisteredClients(
      Pageable pageable) {

    Page<IamClient> pagedResults = clientService.findAllDynamicallyRegistered(pageable);

    ListResponseDTO.Builder<RegisteredClientDTO> resultBuilder = ListResponseDTO.builder();

    return resultBuilder
      .resources(pagedResults.getContent()
        .stream()
        .map(converter::registeredClientDtoFromEntity)
        .collect(Collectors.toList()))
      .fromPage(pagedResults, pageable)
      .build();
  }

  @Override
  public RegisteredClientDTO generateNewClientSecret(String clientId) {
    IamClient client = clientRepository.findByClientId(clientId)
      .orElseThrow(ClientSuppliers.clientNotFound(clientId));

    client.setClientSecret(clientService.generateClientSecret());
    client = clientService.updateClient(client);
    eventPublisher.publishEvent(new ClientSecretUpdatedEvent(this, client));
    return converter.registeredClientDtoFromEntity(client);
  }

  @Override
  public ListResponseDTO<ScimUser> getClientOwners(String clientId, Pageable pageable) {

    Page<IamAccountClient> results = clientService.findClientOwners(clientId, pageable);

    ListResponseDTO.Builder<ScimUser> resultBuilder = ListResponseDTO.builder();

    return resultBuilder
      .resources(results.getContent()
        .stream()
        .map(IamAccountClient::getAccount)
        .map(userConverter::dtoFromEntity)
        .collect(Collectors.toList()))
      .fromPage(results, pageable)
      .build();
  }

  @Override
  public void assignClientOwner(String clientId, String accountId) {

    IamClient client =
        clientRepository.findByClientId(clientId).orElseThrow(clientNotFound(clientId));
    IamAccount account = accountRepo.findByUuid(accountId).orElseThrow(accountNotFound(accountId));
    clientService.linkClientToAccount(client, account);

    eventPublisher.publishEvent(new AccountClientOwnerAssigned(this, account, client));
  }

  @Override
  public void removeClientOwner(String clientId, String accountId) {
    IamClient client =
        clientRepository.findByClientId(clientId).orElseThrow(clientNotFound(clientId));
    IamAccount account = accountRepo.findByUuid(accountId).orElseThrow(accountNotFound(accountId));
    clientService.unlinkClientFromAccount(client, account);

    eventPublisher.publishEvent(new AccountClientOwnerRemoved(this, account, client));
  }


  private IamAccessToken createRegistrationAccessTokenForClient(IamClient client) {
    IamAccessToken token = oidcTokenService.createRegistrationAccessToken(client);
    return tokenService.saveAccessToken(token);

  }

  @Override
  public RegisteredClientDTO rotateRegistrationAccessToken(@NotBlank String clientId) {
    IamClient client =
        clientRepository.findByClientId(clientId).orElseThrow(clientNotFound(clientId));

    IamAccessToken rat =
        Optional.ofNullable(oidcTokenService.rotateRegistrationAccessTokenForClient(client))
          .orElse(createRegistrationAccessTokenForClient(client));

    tokenService.saveAccessToken(rat);

    eventPublisher.publishEvent(new ClientRegistrationAccessTokenRotatedEvent(this, client));

    RegisteredClientDTO response = converter.registeredClientDtoFromEntity(client);
    response.setRegistrationAccessToken(rat.getValue());

    return response;
  }
}
