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

import static java.util.Objects.isNull;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Date;
import java.util.EnumSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;

import org.apache.commons.codec.binary.Base64;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.google.common.collect.Sets;

import it.infn.mw.iam.audit.events.client.ClientCreatedEvent;
import it.infn.mw.iam.authn.util.Authorities;
import it.infn.mw.iam.config.client_registration.ClientRegistrationProperties;
import it.infn.mw.iam.core.IamTokenService;
import it.infn.mw.iam.core.oauth.scope.matchers.DefaultScopeMatcherRegistry;
import it.infn.mw.iam.persistence.model.IamAccessToken;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAccountClient;
import it.infn.mw.iam.persistence.model.IamClient;
import it.infn.mw.iam.persistence.model.IamClient.AuthMethod;
import it.infn.mw.iam.persistence.repository.client.ClientSpecs;
import it.infn.mw.iam.persistence.repository.client.IamAccountClientRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;

@Service
@Transactional
public class DefaultClientService implements ClientService {

  private static final Set<AuthMethod> AUTH_METHODS_REQUIRING_SECRET =
      EnumSet.of(AuthMethod.SECRET_BASIC, AuthMethod.SECRET_POST, AuthMethod.SECRET_JWT);

  private static final int SECRET_SIZE = 512;
  private static final SecureRandom RNG = new SecureRandom();


  private final Clock clock;

  private final IamClientRepository clientRepo;

  private final IamAccountClientRepository accountClientRepo;

  private final ClientRegistrationProperties properties;

  private ApplicationEventPublisher eventPublisher;

  private IamTokenService tokenService;

  public DefaultClientService(Clock clock, IamClientRepository clientRepo,
      IamAccountClientRepository accountClientRepo, ClientRegistrationProperties properties,
      ApplicationEventPublisher eventPublisher, IamTokenService tokenService) {
    this.clock = clock;
    this.clientRepo = clientRepo;
    this.accountClientRepo = accountClientRepo;
    this.properties = properties;
    this.eventPublisher = eventPublisher;
    this.tokenService = tokenService;
  }

  @Override
  public IamClient saveNewClient(IamClient client) {
    client.setCreatedAt(Date.from(clock.instant()));
    eventPublisher.publishEvent(new ClientCreatedEvent(this, client));
    return clientRepo.save(client);
  }

  private Supplier<IamAccountClient> newAccountClient(IamAccount owner, IamClient client) {
    return () -> {
      IamAccountClient ac = new IamAccountClient();
      ac.setAccount(owner);
      ac.setClient(client);
      ac.setCreationTime(Date.from(clock.instant()));
      return accountClientRepo.save(ac);
    };
  }

  @Override
  public IamClient linkClientToAccount(IamClient client, IamAccount owner) {
    IamAccountClient ac = accountClientRepo.findByAccountAndClient(owner, client)
      .orElseGet(newAccountClient(owner, client));
    return ac.getClient();
  }

  @Override
  public IamClient unlinkClientFromAccount(IamClient client, IamAccount owner) {

    accountClientRepo.findByAccountAndClient(owner, client).ifPresent(accountClientRepo::delete);

    return client;
  }

  @Override
  @CacheEvict(cacheNames = DefaultScopeMatcherRegistry.SCOPE_CACHE_KEY, key = "{#client?.id}")
  public IamClient updateClient(IamClient client) {

    return clientRepo.save(client);
  }

  @Override
  public IamClient updateClientStatus(IamClient client, boolean status, String userId) {
    client.setActive(status);
    client.setStatusChangedBy(userId);
    client.setStatusChangedOn(Date.from(clock.instant()));
    return clientRepo.save(client);
  }

  @Override
  public Optional<IamClient> findClientByClientId(String clientId) {
    return clientRepo.findByClientId(clientId);
  }


  @Override
  public Optional<IamClient> findClientByClientIdAndAccount(String clientId, IamAccount account) {

    Optional<IamClient> maybeClient = clientRepo.findByClientId(clientId);

    if (maybeClient.isPresent()) {
      return accountClientRepo.findByAccountAndClientId(account, maybeClient.get().getId())
        .map(IamAccountClient::getClient);
    }

    return Optional.empty();
  }


  @Override
  public void deleteClient(IamClient client) {
    accountClientRepo.deleteByClientId(client.getId());
    deleteTokensByClient(client);
    clientRepo.delete(client);
  }

  private boolean isValidAccessToken(IamAccessToken a) {
    return !(a.getScope().contains("registration-token")
        || a.getScope().contains("resource-token"));
  }

  private void deleteTokensByClient(IamClient client) {
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
  public Page<IamClient> findAll(Pageable page) {
    return clientRepo.findAll(page);
  }


  @Override
  public Page<IamClient> findAllDynamicallyRegistered(Pageable page) {
    return clientRepo.findAll(ClientSpecs.isDynamicallyRegistered(), page);
  }


  @Override
  public Page<IamAccountClient> findClientOwners(String clientId, Pageable page) {

    return accountClientRepo.findByClientClientId(clientId, page);
  }

  @Override
  public IamClient setupClientDefaults(IamClient client) {

    if (isNull(client.getClientId())) {
      client.setClientId(UUID.randomUUID().toString());
    }

    if (client.getAccessTokenValiditySeconds() == null
        || client.getAccessTokenValiditySeconds() == 0) {
      client.setAccessTokenValiditySeconds(
          properties.getClientDefaults().getDefaultAccessTokenValiditySeconds());
    }

    if (client.getRefreshTokenValiditySeconds() == null) {
      client.setRefreshTokenValiditySeconds(
          properties.getClientDefaults().getDefaultRefreshTokenValiditySeconds());
    }

    if (client.getIdTokenValiditySeconds() == null || client.getIdTokenValiditySeconds() == 0) {
      client.setIdTokenValiditySeconds(
          properties.getClientDefaults().getDefaultIdTokenValiditySeconds());
    }

    if (client.getDeviceCodeValiditySeconds() == null
        || client.getDeviceCodeValiditySeconds() == 0) {
      client.setDeviceCodeValiditySeconds(
          properties.getClientDefaults().getDefaultDeviceCodeValiditySeconds());
    }

    client.setAllowIntrospection(true);

    if (isNull(client.getTokenEndpointAuthMethod())) {
      client.setTokenEndpointAuthMethod(AuthMethod.SECRET_BASIC);
    }

    if (isNull(client.getClientSecret())
        && AUTH_METHODS_REQUIRING_SECRET.contains(client.getTokenEndpointAuthMethod())) {
      client.setClientSecret(generateClientSecret());
    }

    client.setAuthorities(Sets.newHashSet(Authorities.ROLE_CLIENT));
    return client;
  }

  @Override
  public String generateClientSecret() {
    return Base64.encodeBase64URLSafeString(new BigInteger(SECRET_SIZE, RNG).toByteArray())
      .replace("=", "");
  }

}
