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
import static it.infn.mw.iam.config.client_registration.ClientRegistrationProperties.ClientRegistrationAuthorizationPolicy.ADMINISTRATORS;
import static it.infn.mw.iam.core.oauth.scope.IamSystemScopeService.ADMIN_READ_SCOPE;
import static it.infn.mw.iam.core.oauth.scope.IamSystemScopeService.ADMIN_WRITE_SCOPE;

import java.text.ParseException;
import java.time.Clock;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.validation.constraints.NotBlank;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.annotation.Validated;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.client.management.validation.OnClientCreation;
import it.infn.mw.iam.api.client.management.validation.OnClientUpdate;
import it.infn.mw.iam.api.client.service.ClientConverter;
import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.api.client.service.ClientUtils;
import it.infn.mw.iam.api.client.util.ClientSuppliers;
import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.common.PagingUtils;
import it.infn.mw.iam.api.common.client.AuthorizationGrantType;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.api.common.client.TokenEndpointAuthenticationMethod;
import it.infn.mw.iam.api.scim.converter.UserConverter;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.audit.events.account.client.AccountClientOwnerAssigned;
import it.infn.mw.iam.audit.events.account.client.AccountClientOwnerRemoved;
import it.infn.mw.iam.audit.events.client.ClientRemovedEvent;
import it.infn.mw.iam.audit.events.client.ClientSecretUpdatedEvent;
import it.infn.mw.iam.audit.events.client.ClientStatusChangedEvent;
import it.infn.mw.iam.audit.events.client.ClientUpdatedEvent;
import it.infn.mw.iam.core.client.IamSha256PasswordEncoder;
import it.infn.mw.iam.api.common.error.NoSuchAccountError;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.DashboardProperties;
import it.infn.mw.iam.config.client_registration.ClientRegistrationProperties;
import it.infn.mw.iam.core.oauth.profile.RegistrationTokenService;
import it.infn.mw.iam.core.userinfo.OAuth2AuthenticationScopeResolver;
import it.infn.mw.iam.notification.NotificationFactory;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.model.ClientRelyingPartyEntity;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAccountClient;
import it.infn.mw.iam.persistence.model.OAuth2AccessTokenEntity;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.client.IamAccountClientRepository;

@SuppressWarnings("deprecation")
@Service
@Validated
@Transactional
public class DefaultClientManagementService implements ClientManagementService {

  private static final String NOT_AN_OWNER_ERROR = "Only the owners of a client can manage it";
  private static final String SENIOR_OWNER_ERROR =
      "Owners can only be removed by an owner that was added before them";

  private static final Comparator<IamAccountClient> BY_SENIORITY =
      Comparator.comparing(IamAccountClient::getCreationTime)
        .thenComparing(IamAccountClient::getId);

  private final Clock clock;
  private final ClientService clientService;
  private final ClientConverter converter;
  private final ClientUtils clientUtils;
  private final UserConverter userConverter;
  private final IamAccountRepository accountRepo;
  private final IamAccountClientRepository accountClientRepo;
  private final AccountUtils accountUtils;
  private final OAuth2AuthenticationScopeResolver scopeResolver;
  private final ClientRegistrationProperties registrationProperties;
  private final IamProperties iamProperties;
  private final RegistrationTokenService registrationTokenService;
  private final ApplicationEventPublisher eventPublisher;
  private final NotificationFactory notificationFactory;

  public DefaultClientManagementService(Clock clock, ClientService clientService,
      ClientConverter converter, ClientUtils clientUtils, UserConverter userConverter,
      IamAccountRepository accountRepo, IamAccountClientRepository accountClientRepo,
      AccountUtils accountUtils, OAuth2AuthenticationScopeResolver scopeResolver,
      ClientRegistrationProperties registrationProperties, IamProperties iamProperties,
      RegistrationTokenService registrationTokenService, ApplicationEventPublisher aep,
      NotificationFactory notificationFactory) {
    this.clock = clock;
    this.clientService = clientService;
    this.converter = converter;
    this.clientUtils = clientUtils;
    this.userConverter = userConverter;
    this.accountRepo = accountRepo;
    this.accountClientRepo = accountClientRepo;
    this.accountUtils = accountUtils;
    this.scopeResolver = scopeResolver;
    this.registrationProperties = registrationProperties;
    this.iamProperties = iamProperties;
    this.registrationTokenService = registrationTokenService;
    this.eventPublisher = aep;
    this.notificationFactory = notificationFactory;
  }

  @Override
  public ListResponseDTO<RegisteredClientDTO> retrieveAllClients(Pageable pageable) {

    Page<ClientDetailsEntity> pagedResults = clientService.findAll(pageable);

    ListResponseDTO.Builder<RegisteredClientDTO> resultBuilder = ListResponseDTO.builder();

    return resultBuilder
      .resources(
          pagedResults.getContent().stream().map(converter::registeredClientDtoFromEntity).toList())
      .fromPage(pagedResults, pageable)
      .build();
  }

  @Override
  public List<RegisteredClientDTO> retrieveAllClients() {

    return clientService.findAll().stream().map(converter::registeredClientDtoFromEntity).toList();
  }

  @Override
  public Optional<RegisteredClientDTO> retrieveClientByClientId(String clientId) {
    return clientService.findClientByClientId(clientId)
      .map(converter::registeredClientDtoFromEntity);
  }

  @Validated(OnClientCreation.class)
  @Override
  public RegisteredClientDTO saveNewClient(RegisteredClientDTO client) throws ParseException {

    rejectPublicClientCredentials(client);

    ClientDetailsEntity entity = converter.entityFromClientManagementRequest(client);
    entity.setDynamicallyRegistered(false);
    entity.setCreatedAt(Date.from(clock.instant()));
    entity.setActive(true);

    if (hasRelyingParty(client)) {
      ClientRelyingPartyEntity clientRelyingParty =
          new ClientRelyingPartyEntity(entity, client.getExpiration(), client.getEntityId());
      entity.setClientRelyingParty(clientRelyingParty);
      entity.setRequestObjectSigningAlg(client.getRequestObjectSigningAlgorithm());
    }

    clientUtils.setupClientDefaults(entity);

    String plainClientSecret = entity.getClientSecret();
    String hashedClientSecret = new IamSha256PasswordEncoder().encode(plainClientSecret);
    entity.setClientSecret(hashedClientSecret);

    entity = clientService.saveNewClient(entity);

    RegisteredClientDTO newClient = converter.registeredClientDtoFromEntity(entity);
    newClient.setClientSecret(plainClientSecret);

    return newClient;
  }

  private void rejectPublicClientCredentials(RegisteredClientDTO client) {
    if (TokenEndpointAuthenticationMethod.none.equals(client.getTokenEndpointAuthMethod())
        && client.getGrantTypes() != null
        && client.getGrantTypes().contains(AuthorizationGrantType.CLIENT_CREDENTIALS)) {
      throw new InvalidRequestException(
          "Public clients cannot use the client_credentials grant");
    }
  }

  private boolean hasRelyingParty(RegisteredClientDTO request) {
    return request.getEntityId() != null;
  }

  @Override
  public void deleteClientByClientId(String clientId) {

    ClientDetailsEntity client = clientService.findClientByClientId(clientId)
      .orElseThrow(ClientSuppliers.clientNotFound(clientId));

    clientService.deleteClient(client);
    eventPublisher.publishEvent(new ClientRemovedEvent(this, client));
  }

  @Override
  public void updateClientStatus(String clientId, boolean status, String userId) {

    ClientDetailsEntity client = clientService.findClientByClientId(clientId)
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
  public RegisteredClientDTO updateClient(String clientId, RegisteredClientDTO clientDTO)
      throws ParseException {

    rejectPublicClientCredentials(clientDTO);

    ClientDetailsEntity oldClient = clientService.findClientByClientId(clientId)
      .orElseThrow(ClientSuppliers.clientNotFound(clientId));

    if (oldClient.getClientRelyingParty() != null && !oldClient.getClientId().startsWith("https")) {
      throw new InvalidRequestException("Federated clients cannot be updated");
    }

    ClientDetailsEntity newClient = converter.entityFromClientManagementRequest(clientDTO);

    newClient.setId(oldClient.getId());
    if (ClientUtils.AUTH_METHODS_REQUIRING_SECRET.contains(newClient.getTokenEndpointAuthMethod())
        && Objects.isNull(oldClient.getClientSecret())) {
      String plainClientSecret = clientUtils.generateClientSecret();
      newClient.setClientSecret(new IamSha256PasswordEncoder().encode(plainClientSecret));
    } else if (!ClientUtils.AUTH_METHODS_REQUIRING_SECRET
      .contains(newClient.getTokenEndpointAuthMethod())
        && !Objects.isNull(oldClient.getClientSecret())) {
      newClient.setClientSecret(null);
    } else {
      newClient.setClientSecret(oldClient.getClientSecret());
    }
    newClient.setCreatedAt(oldClient.getCreatedAt());
    newClient.setClientId(oldClient.getClientId());
    newClient.setAuthorities(oldClient.getAuthorities());
    newClient.setDynamicallyRegistered(oldClient.isDynamicallyRegistered());
    newClient.setActive(oldClient.isActive());

    if (hasRelyingParty(clientDTO)) {
      ClientRelyingPartyEntity clientRelyingParty = new ClientRelyingPartyEntity(newClient,
          clientDTO.getExpiration(), clientDTO.getEntityId());
      newClient.setClientRelyingParty(clientRelyingParty);
      newClient.setRequestObjectSigningAlg(clientDTO.getRequestObjectSigningAlgorithm());
      newClient.setActive(true);
    }

    newClient = clientService.updateClient(newClient);
    eventPublisher.publishEvent(new ClientUpdatedEvent(this, newClient));
    return converter.registeredClientDtoFromEntity(newClient);
  }

  @Override
  public ListResponseDTO<RegisteredClientDTO> retrieveAllDynamicallyRegisteredClients(
      Pageable pageable) {

    Page<ClientDetailsEntity> pagedResults = clientService.findAllDynamicallyRegistered(pageable);

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
    ClientDetailsEntity client = clientService.findClientByClientId(clientId)
      .orElseThrow(ClientSuppliers.clientNotFound(clientId));

    String plainClientSecret = clientUtils.generateClientSecret();
    client.setClientSecret(new IamSha256PasswordEncoder().encode(plainClientSecret));

    client = clientService.updateClient(client);
    eventPublisher.publishEvent(new ClientSecretUpdatedEvent(this, client));

    RegisteredClientDTO updatedClient = converter.registeredClientDtoFromEntity(client);
    updatedClient.setClientSecret(plainClientSecret);

    return updatedClient;
  }

  @Override
  public ListResponseDTO<ScimUser> getClientOwners(String clientId, Pageable pageable) {

    Page<IamAccountClient> results = clientService.findClientOwners(clientId, pageable);
    boolean administrator = isAdministrator(ADMIN_READ_SCOPE);

    if (!administrator) {
      checkOwnersCanManageOwners();
    }

    ListResponseDTO.Builder<ScimUser> resultBuilder = ListResponseDTO.builder();

    return resultBuilder
      .resources(results.getContent()
        .stream()
        .map(IamAccountClient::getAccount)
        .map(a -> administrator ? userConverter.dtoFromEntity(a) : ownerSummary(a))
        .collect(Collectors.toList()))
      .fromPage(results, pageable)
      .build();
  }

  private ScimUser ownerSummary(IamAccount account) {
    return ScimUser.builder()
      .id(account.getUuid())
      .userName(account.getUsername())
      .buildName(account.getUserInfo().getGivenName(), account.getUserInfo().getFamilyName())
      .build();
  }

  @Override
  public void assignClientOwner(String clientId, String accountId) {

    lockOwnersCheckingCaller(clientId);
    ClientDetailsEntity client =
        clientService.findClientByClientId(clientId).orElseThrow(clientNotFound(clientId));
    IamAccount account = accountRepo.findByUuid(accountId).orElseThrow(accountNotFound(accountId));
    assignClientOwner(client, account);
  }

  @Override
  public void assignClientOwnerByUsername(String clientId, String username) {

    lockOwnersCheckingCaller(clientId);
    ClientDetailsEntity client =
        clientService.findClientByClientId(clientId).orElseThrow(clientNotFound(clientId));
    IamAccount account = accountRepo.findByUsername(username)
      .orElseThrow(() -> NoSuchAccountError.forUsername(username));
    assignClientOwner(client, account);
  }

  private void assignClientOwner(ClientDetailsEntity client, IamAccount account) {

    clientService.linkClientToAccount(client, account);

    eventPublisher.publishEvent(new AccountClientOwnerAssigned(this, account, client));
  }

  @Override
  public void removeClientOwner(String clientId, String accountId) {

    List<IamAccountClient> owners = accountClientRepo.findByClientClientIdForUpdate(clientId);
    Optional<IamAccount> owner = callerUnlessAdministrator(owners);
    ClientDetailsEntity client =
        clientService.findClientByClientId(clientId).orElseThrow(clientNotFound(clientId));
    IamAccount account = accountRepo.findByUuid(accountId).orElseThrow(accountNotFound(accountId));

    owner.ifPresent(caller -> checkRemovalByOwner(owners, caller, account));

    clientService.unlinkClientFromAccount(client, account);

    eventPublisher.publishEvent(new AccountClientOwnerRemoved(this, account, client));
  }

  private void checkRemovalByOwner(List<IamAccountClient> owners, IamAccount caller,
      IamAccount account) {

    if (caller.equals(account)) {
      if (owners.size() == 1) {
        throw new InvalidRequestException("Clients must have at least one owner");
      }
      return;
    }

    List<IamAccount> bySeniority =
        owners.stream().sorted(BY_SENIORITY).map(IamAccountClient::getAccount).toList();
    int position = bySeniority.indexOf(account);

    if (position >= 0 && position < bySeniority.indexOf(caller)) {
      throw new AccessDeniedException(SENIOR_OWNER_ERROR);
    }
  }

  // Same rule as the controller: the administrator scope, or the role without a token
  private boolean isAdministrator(String adminScope) {

    Authentication authn = SecurityContextHolder.getContext().getAuthentication();

    if (authn instanceof OAuth2Authentication oauth) {
      return scopeResolver.resolveScope(oauth).contains(adminScope);
    }

    return authn == null || accountUtils.isAdmin(authn);
  }

  /**
   * Owners manage owners where users can register clients, and only from a session or with a
   * token issued to the IAM dashboard: a token issued to another client gives no right on the
   * clients of its user.
   */
  private void checkOwnersCanManageOwners() {

    if (ADMINISTRATORS.equals(registrationProperties.getAllowFor())) {
      throw new AccessDeniedException("Only administrators can manage the owners of a client");
    }

    Authentication authn = SecurityContextHolder.getContext().getAuthentication();
    DashboardProperties dashboard = iamProperties.getDashboard();

    if (authn instanceof OAuth2Authentication oauth && !(dashboard.isEnabled()
        && oauth.getOAuth2Request().getClientId().equals(dashboard.getClientId()))) {
      throw new AccessDeniedException("Owners are managed from the IAM dashboard");
    }
  }

  // The lock serializes the changes of the owners and must be the first read of the transaction
  private void lockOwnersCheckingCaller(String clientId) {
    callerUnlessAdministrator(accountClientRepo.findByClientClientIdForUpdate(clientId));
  }

  private Optional<IamAccount> callerUnlessAdministrator(List<IamAccountClient> owners) {

    if (isAdministrator(ADMIN_WRITE_SCOPE)) {
      return Optional.empty();
    }

    checkOwnersCanManageOwners();

    return Optional.of(accountUtils.getAuthenticatedUserAccount()
      .filter(caller -> owners.stream().anyMatch(o -> o.getAccount().equals(caller)))
      .orElseThrow(() -> new AccessDeniedException(NOT_AN_OWNER_ERROR)));
  }

  @Override
  public RegisteredClientDTO rotateRegistrationAccessToken(@NotBlank String clientId) {

    ClientDetailsEntity client =
        clientService.findClientByClientId(clientId).orElseThrow(clientNotFound(clientId));

    OAuth2AccessTokenEntity rat =
        registrationTokenService.rotateRegistrationAccessTokenForClient(client);

    RegisteredClientDTO response = converter.registeredClientDtoFromEntity(client);
    response.setRegistrationAccessToken(rat.getValue());
    return response;
  }

}
