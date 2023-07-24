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
package it.infn.mw.iam.api.client.service;

import java.time.Clock;
import java.util.Date;
import java.util.Optional;
import java.util.function.Supplier;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.service.OAuth2TokenEntityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.oauth2.provider.OAuth2RequestValidator;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.audit.events.client.ClientCreatedEvent;
import it.infn.mw.iam.core.oauth.scope.matchers.DefaultScopeMatcherRegistry;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAccountClient;
import it.infn.mw.iam.persistence.repository.client.ClientSpecs;
import it.infn.mw.iam.persistence.repository.client.IamAccountClientRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;

@Service
@Transactional
@SuppressWarnings("deprecation")
public class DefaultClientService implements ClientService {

  private final Clock clock;

  private final IamClientRepository clientRepo;

  private final IamAccountClientRepository accountClientRepo;

  private ApplicationEventPublisher eventPublisher;

  private OAuth2TokenEntityService tokenService;

  @Autowired
  public DefaultClientService(Clock clock, IamClientRepository clientRepo,
      IamAccountClientRepository accountClientRepo, ApplicationEventPublisher eventPublisher,
      OAuth2RequestValidator requestValidator, OAuth2TokenEntityService tokenService) {
    this.clock = clock;
    this.clientRepo = clientRepo;
    this.accountClientRepo = accountClientRepo;
    this.eventPublisher = eventPublisher;
    this.tokenService = tokenService;
  }

  @Override
  public ClientDetailsEntity saveNewClient(ClientDetailsEntity client) {
    client.setCreatedAt(Date.from(clock.instant()));
    eventPublisher.publishEvent(new ClientCreatedEvent(this, client));
    return clientRepo.save(client);
  }


  private Supplier<IamAccountClient> newAccountClient(IamAccount owner,
      ClientDetailsEntity client) {
    return () -> {
      IamAccountClient ac = new IamAccountClient();
      ac.setAccount(owner);
      ac.setClient(client);
      ac.setCreationTime(Date.from(clock.instant()));
      return accountClientRepo.save(ac);
    };
  }

  @Override
  public ClientDetailsEntity linkClientToAccount(ClientDetailsEntity client, IamAccount owner) {
    IamAccountClient ac = accountClientRepo.findByAccountAndClient(owner, client)
      .orElseGet(newAccountClient(owner, client));
    return ac.getClient();
  }

  @Override
  public ClientDetailsEntity unlinkClientFromAccount(ClientDetailsEntity client, IamAccount owner) {

    accountClientRepo.findByAccountAndClient(owner, client).ifPresent(accountClientRepo::delete);

    return client;
  }

  @Override
  @CacheEvict(cacheNames = DefaultScopeMatcherRegistry.SCOPE_CACHE_KEY, key = "{#client?.id}")
  public ClientDetailsEntity updateClient(ClientDetailsEntity client) {

    return clientRepo.save(client);
  }


  @Override
  public Optional<ClientDetailsEntity> findClientByClientId(String clientId) {
    return clientRepo.findByClientId(clientId);
  }


  @Override
  public Optional<ClientDetailsEntity> findClientByClientIdAndAccount(String clientId,
      IamAccount account) {

    Optional<ClientDetailsEntity> maybeClient = clientRepo.findByClientId(clientId);

    if (maybeClient.isPresent()) {
      return accountClientRepo.findByAccountAndClientId(account, maybeClient.get().getId())
        .map(IamAccountClient::getClient);
    }

    return Optional.empty();
  }


  @Override
  public void deleteClient(ClientDetailsEntity client) {
    accountClientRepo.deleteByClientId(client.getId());
    deleteTokensByClient(client);
    clientRepo.delete(client);
  }

  private boolean isValidAccessToken(OAuth2AccessTokenEntity a) {
    return !(a.getAuthenticationHolder().getScope().contains("registration-token")
        || a.getAuthenticationHolder().getScope().contains("resource-token"));
  }

  private void deleteTokensByClient(ClientDetailsEntity client) {
    // delete all valid access tokens (exclude registration and resource tokens)
    tokenService.getAccessTokensForClient(client)
      .stream()
      .filter(this::isValidAccessToken)
      .forEach(at -> tokenService.revokeAccessToken(at));
    // delete all valid refresh tokens
    tokenService.getRefreshTokensForClient(client)
      .forEach(rt -> tokenService.revokeRefreshToken(rt));
  }

  @Override
  public Page<ClientDetailsEntity> findAll(Pageable page) {
    return clientRepo.findAll(page);
  }


  @Override
  public Page<ClientDetailsEntity> findAllDynamicallyRegistered(Pageable page) {
    return clientRepo.findAll(ClientSpecs.isDynamicallyRegistered(), page);
  }


  @Override
  public Page<IamAccountClient> findClientOwners(String clientId, Pageable page) {

    return accountClientRepo.findByClientClientId(clientId, page);

  }

}
