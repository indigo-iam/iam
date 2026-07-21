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
package it.infn.mw.iam.api.client.registration.service;

import static it.infn.mw.iam.api.client.util.ClientSuppliers.clientNotFound;
import static it.infn.mw.iam.config.client_registration.ClientRegistrationProperties.ClientRegistrationAuthorizationPolicy.ADMINISTRATORS;
import static it.infn.mw.iam.config.client_registration.ClientRegistrationProperties.ClientRegistrationAuthorizationPolicy.ANYONE;
import static it.infn.mw.iam.config.client_registration.ClientRegistrationProperties.ClientRegistrationAuthorizationPolicy.REGISTERED_USERS;
import static java.util.Objects.isNull;
import static java.util.stream.Collectors.toSet;

import java.text.ParseException;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;

import javax.validation.constraints.NotBlank;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.ClientRelyingPartyEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.service.SystemScopeService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.stereotype.Service;
import org.springframework.validation.annotation.Validated;

import com.google.common.base.Strings;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.client.error.ClientSuspended;
import it.infn.mw.iam.api.client.error.InvalidClientRegistrationRequest;
import it.infn.mw.iam.api.client.registration.validation.OnDynamicClientRegistration;
import it.infn.mw.iam.api.client.registration.validation.OnDynamicClientUpdate;
import it.infn.mw.iam.api.client.service.ClientConverter;
import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.api.client.service.ClientUtils;
import it.infn.mw.iam.api.common.client.AuthorizationGrantType;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.audit.events.account.client.AccountClientOwnerAssigned;
import it.infn.mw.iam.audit.events.client.ClientRegistered;
import it.infn.mw.iam.audit.events.client.ClientRemovedEvent;
import it.infn.mw.iam.audit.events.client.ClientUpdatedEvent;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.ClientProperties;
import it.infn.mw.iam.config.client_registration.ClientRegistrationProperties;
import it.infn.mw.iam.config.client_registration.ClientRegistrationProperties.ClientRegistrationAuthorizationPolicy;
import it.infn.mw.iam.core.client.IamHmacPasswordEncoder;
import it.infn.mw.iam.core.oauth.profile.RegistrationTokenService;
import it.infn.mw.iam.core.oauth.scope.IamSystemScopeService;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcher;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcherRegistry;
import it.infn.mw.iam.persistence.model.IamAccount;

@Service
@ConditionalOnProperty(name = "client-registration.enable", havingValue = "true",
    matchIfMissing = false)
@Validated
@SuppressWarnings("deprecation")
public class DefaultClientRegistrationService implements ClientRegistrationService {

  public static final String INVALID_ACCESS_TOKEN_ERROR = "Invalid registration access token";
  public static final String NO_AUTH_USER_ERROR = "No authenticated user found";
  public static final String ACCESS_DENIED_ERROR =
      "You do not have enough privileges to access this client registration API";

  public static final String GRANT_TYPE_NOT_ALLOWED_ERROR_STR = "Grant type not allowed: %s";

  private static final EnumSet<AuthorizationGrantType> FORBIDDEN_GRANT_TYPES_FOR_USER =
      EnumSet.of(AuthorizationGrantType.PASSWORD, AuthorizationGrantType.TOKEN_EXCHANGE);
  private static final EnumSet<AuthorizationGrantType> FORBIDDEN_GRANT_TYPES_FOR_ANONYMOUS =
      EnumSet.of(AuthorizationGrantType.PASSWORD, AuthorizationGrantType.TOKEN_EXCHANGE,
          AuthorizationGrantType.CLIENT_CREDENTIALS);

  private final ClientService clientService;
  private final AccountUtils accountUtils;
  private final ClientConverter converter;
  private final ClientUtils clientUtils;
  private final ClientProperties clientProperties;
  private final RegistrationTokenService registrationTokenService;
  private final ResourceServerTokenServices resourceServer;
  private final SystemScopeService systemScopeService;
  private final ClientRegistrationProperties registrationProperties;
  private final ScopeMatcherRegistry scopeMatcherRegistry;
  private final ApplicationEventPublisher eventPublisher;

  public DefaultClientRegistrationService(ClientService clientService, AccountUtils accountUtils,
      ClientConverter converter, ClientUtils clientUtils, IamProperties iamProperties,
      RegistrationTokenService registrationTokenService, ResourceServerTokenServices resourceServer,
      SystemScopeService scopeService, ClientRegistrationProperties registrationProperties,
      ScopeMatcherRegistry scopeMatcherRegistry, ApplicationEventPublisher aep) {

    this.clientService = clientService;
    this.accountUtils = accountUtils;
    this.converter = converter;
    this.clientUtils = clientUtils;
    this.clientProperties = iamProperties.getClient();
    this.registrationTokenService = registrationTokenService;
    this.resourceServer = resourceServer;
    this.systemScopeService = scopeService;
    this.registrationProperties = registrationProperties;
    this.scopeMatcherRegistry = scopeMatcherRegistry;
    this.eventPublisher = aep;

  }

  private void throwGrantTypeNotAllowed(AuthorizationGrantType gt) {
    throw new InvalidClientRegistrationRequest(
        String.format(GRANT_TYPE_NOT_ALLOWED_ERROR_STR, gt.getGrantType()));
  }

  private Supplier<InvalidClientRegistrationRequest> noAuthUserError() {
    return () -> new InvalidClientRegistrationRequest(NO_AUTH_USER_ERROR);
  }

  protected boolean isAnonymous(Authentication authentication) {
    if (authentication instanceof OAuth2Authentication oa) {
      return isNull(oa.getUserAuthentication());
    }
    return isNull(authentication) || (authentication instanceof AnonymousAuthenticationToken);
  }

  private void checkAllowedGrantTypes(RegisteredClientDTO request, Authentication authentication) {

    if (accountUtils.isAdmin(authentication)) {
      return;
    }
    if (accountUtils.isRegisteredUser(authentication)) {
      request.getGrantTypes()
        .stream()
        .filter(FORBIDDEN_GRANT_TYPES_FOR_USER::contains)
        .findFirst()
        .ifPresent(this::throwGrantTypeNotAllowed);
    } else {
      request.getGrantTypes()
        .stream()
        .filter(FORBIDDEN_GRANT_TYPES_FOR_ANONYMOUS::contains)
        .findFirst()
        .ifPresent(this::throwGrantTypeNotAllowed);
    }
  }

  private void checkAllowedGrantTypesOnUpdate(RegisteredClientDTO request,
      Authentication authentication, ClientDetailsEntity oldClient) {

    if (accountUtils.isAdmin(authentication)) {
      return;
    }
    if (accountUtils.isRegisteredUser(authentication)) {
      request.getGrantTypes()
        .stream()
        .filter(s -> !oldClient.getGrantTypes().contains(s.getGrantType()))
        .filter(FORBIDDEN_GRANT_TYPES_FOR_USER::contains)
        .findFirst()
        .ifPresent(this::throwGrantTypeNotAllowed);
    } else {
      request.getGrantTypes()
        .stream()
        .filter(s -> !oldClient.getGrantTypes().contains(s.getGrantType()))
        .filter(FORBIDDEN_GRANT_TYPES_FOR_ANONYMOUS::contains)
        .findFirst()
        .ifPresent(this::throwGrantTypeNotAllowed);
    }
  }

  private void cleanupRequestedScopesOnUpdate(RegisteredClientDTO request,
      Authentication authentication, ClientDetailsEntity oldClient) {

    IamSystemScopeService.RESERVED_VALUES.forEach(request.getScope()::remove);

    if (!accountUtils.isAdmin(authentication)) {
      Set<ScopeMatcher> matchers = systemScopeService.getRestricted()
        .stream()
        .map(s -> scopeMatcherRegistry.findMatcherForScope(s.getValue()))
        .collect(toSet());

      Set<String> filteredClientScopes = request.getScope()
        .stream()
        .filter(s -> matchers.stream()
          .noneMatch(m -> m.matches(s) && !oldClient.getScope().contains(s)))
        .collect(toSet());

      request.setScope(filteredClientScopes);
    }

  }

  private void removeRestrictedScopes(ClientDetailsEntity entity) {
    Set<ScopeMatcher> matchers = systemScopeService.getRestricted()
      .stream()
      .map(s -> scopeMatcherRegistry.findMatcherForScope(s.getValue()))
      .collect(toSet());

    Set<String> filteredClientScopes = entity.getScope()
      .stream()
      .filter(s -> matchers.stream().noneMatch(m -> m.matches(s)))
      .collect(toSet());

    entity.setScope(filteredClientScopes);
  }

  private void removeCustomScopes(ClientDetailsEntity entity) {
    Set<ScopeMatcher> matchers = systemScopeService.getAll()
      .stream()
      .map(s -> scopeMatcherRegistry.findMatcherForScope(s.getValue()))
      .collect(toSet());

    Set<String> filteredClientScopes = entity.getScope()
      .stream()
      .filter(s -> matchers.stream().anyMatch(m -> m.matches(s)))
      .collect(toSet());

    entity.setScope(filteredClientScopes);
  }

  private void cleanupRequestedScopes(ClientDetailsEntity entity, Authentication authentication) {

    if (entity.getScope().isEmpty()) {
      entity.getScope().addAll(systemScopeService.toStrings(systemScopeService.getDefaults()));
    } else {
      IamSystemScopeService.RESERVED_VALUES.forEach(entity.getScope()::remove);
      if (registrationProperties.isAdminOnlyCustomScopes()
          && !accountUtils.isAdmin(authentication)) {
        removeCustomScopes(entity);
      }
      if (!accountUtils.isAdmin(authentication)) {
        removeRestrictedScopes(entity);
      }
    }
  }

  private void authzChecks(Authentication authentication) {
    ClientRegistrationAuthorizationPolicy allowedForRegistration =
        registrationProperties.getAllowFor();

    boolean registrationAllowed =
        (ADMINISTRATORS.equals(allowedForRegistration) && accountUtils.isAdmin(authentication))
            || (REGISTERED_USERS.equals(allowedForRegistration)
                && accountUtils.isRegisteredUser(authentication))
            || (ANYONE.equals(allowedForRegistration));

    if (!registrationAllowed) {
      throw new AccessDeniedException(ACCESS_DENIED_ERROR);
    }

  }

  private boolean registrationAccessTokenAuthenticationValidForClientId(String clientId,
      Authentication authentication) {
    if (authentication instanceof OAuth2Authentication oauth) {
      return oauth.getOAuth2Request().getClientId().equals(clientId) && oauth.getOAuth2Request()
        .getScope()
        .contains(SystemScopeService.REGISTRATION_TOKEN_SCOPE);
    }
    return false;
  }

  private boolean resourceAccessTokenAuthenticationValidForClientId(String clientId,
      Authentication authentication) {
    if (authentication instanceof OAuth2Authentication oauth) {
      return oauth.getOAuth2Request().getClientId().equals(clientId)
          && oauth.getOAuth2Request().getScope().contains(SystemScopeService.RESOURCE_TOKEN_SCOPE);
    }
    return false;
  }

  private boolean registrationAccessTokenValueValidForClientId(String clientId, String rat) {

    try {

      OAuth2AccessTokenEntity token = (OAuth2AccessTokenEntity) resourceServer.readAccessToken(rat);

      var hasRegistrationScope =
          token.getScope().contains(SystemScopeService.REGISTRATION_TOKEN_SCOPE);

      var matchesClientId = token.getClient().getClientId().equals(clientId);

      return hasRegistrationScope && matchesClientId;

    } catch (Exception e) {
      return false;
    }
  }

  private void checkUserUpdatingSuspendedClient(Authentication authentication,
      ClientDetailsEntity oldClient) {
    if (accountUtils.isAdmin(authentication)) {
      return;
    }
    if (!oldClient.isActive()) {
      throw new ClientSuspended("Client " + oldClient.getClientId() + " is suspended!");
    }
  }

  private boolean hasRelyingParty(RegisteredClientDTO request) {
    return request.getEntityId() != null;
  }

  @Validated(OnDynamicClientRegistration.class)
  @Override
  public RegisteredClientDTO registerClient(RegisteredClientDTO request,
      Authentication authentication) throws ParseException {

    authzChecks(authentication);

    ClientDetailsEntity client = converter.entityFromRegistrationRequest(request);
    clientUtils.setupClientDefaults(client);
    client.setDynamicallyRegistered(true);
    client.setActive(true);
    // only allow to disable upscoping for admins
    if (accountUtils.isAdmin(authentication)) {
      client.setUpScopingEnabled(request.isUpScopingEnabled());
    } else {
      client.setUpScopingEnabled(true);
    }

    if (hasRelyingParty(request)) {
      ClientRelyingPartyEntity clientRelyingParty =
          new ClientRelyingPartyEntity(client, request.getExpiration(), request.getEntityId());
      client.setClientRelyingParty(clientRelyingParty);
    }

    checkAllowedGrantTypes(request, authentication);
    cleanupRequestedScopes(client, authentication);

    String plainClientSecret = client.getClientSecret();
    hashClientSecret(client, plainClientSecret);

    client = clientService.saveNewClient(client);

    RegisteredClientDTO response = converter.registrationResponseFromClient(client);

    response.setClientSecret(plainClientSecret);

    if (!hasRelyingParty(request) && isAnonymous(authentication)) {

      OAuth2AccessTokenEntity ratEntity =
          registrationTokenService.createRegistrationAccessToken(client);
      response.setRegistrationAccessToken(ratEntity.getValue());

    } else if (!isAnonymous(authentication)) {

      IamAccount account =
          accountUtils.getAuthenticatedUserAccount(authentication).orElseThrow(noAuthUserError());

      client.getContacts().add(account.getUserInfo().getEmail());

      clientService.linkClientToAccount(client, account);
    }

    eventPublisher.publishEvent(new ClientRegistered(this, client));

    return response;
  }

  private void hashClientSecret(ClientDetailsEntity client, String secret) {
    if (!Strings.isNullOrEmpty(secret)) {

      String hashedClientSecret =
          new IamHmacPasswordEncoder(clientProperties.getSecretEncoderKey()).encode(secret);
      client.setClientSecret(hashedClientSecret);
    }
  }

  @Override
  public RegisteredClientDTO registerProtectedResource(RegisteredClientDTO request,
      Authentication authentication) throws ParseException {

    authzChecks(authentication);

    ClientDetailsEntity client = converter.entityFromRegistrationRequest(request);
    clientUtils.setupProtectedResourceDefaults(client);
    client.setClientId(UUID.randomUUID().toString());
    cleanupRequestedScopes(client, authentication);

    Optional<IamAccount> account = accountUtils.getAuthenticatedUserAccount(authentication);

    if (account.isPresent()) {
      client.getContacts().add(account.get().getUserInfo().getEmail());
    }

    String plainClientSecret = client.getClientSecret();
    hashClientSecret(client, plainClientSecret);

    client = clientService.saveNewClient(client);
    eventPublisher.publishEvent(new ClientRegistered(this, client));

    if (account.isPresent()) {
      clientService.linkClientToAccount(client, account.get());
    }

    RegisteredClientDTO response = converter.registrationResponseFromClient(client);

    response.setClientSecret(plainClientSecret);

    OAuth2AccessTokenEntity ratEntity = registrationTokenService.createResourceAccessToken(client);
    response.setRegistrationAccessToken(ratEntity.getValue());

    return response;
  }

  private Optional<ClientDetailsEntity> lookupClient(String clientId,
      Authentication authentication) {

    if (isAnonymous(authentication)) {
      if (!registrationAccessTokenAuthenticationValidForClientId(clientId, authentication)) {
        throw new InvalidClientRegistrationRequest(INVALID_ACCESS_TOKEN_ERROR);
      }

      return clientService.findClientByClientId(clientId);
    }
    IamAccount account =
        accountUtils.getAuthenticatedUserAccount(authentication).orElseThrow(noAuthUserError());

    return clientService.findClientByClientIdAndAccount(clientId, account);
  }

  @Override
  public RegisteredClientDTO retrieveClient(String clientId, Authentication authentication) {
    authzChecks(authentication);

    return lookupClient(clientId, authentication).map(converter::registrationResponseFromClient)
      .orElseThrow(clientNotFound(clientId));
  }

  private Optional<ClientDetailsEntity> lookupProtectedResource(String clientId,
      Authentication authentication) {

    if (isAnonymous(authentication)) {
      if (!resourceAccessTokenAuthenticationValidForClientId(clientId, authentication)) {
        throw new InvalidClientRegistrationRequest(INVALID_ACCESS_TOKEN_ERROR);
      }

      return clientService.findClientByClientId(clientId);
    }
    IamAccount account =
        accountUtils.getAuthenticatedUserAccount(authentication).orElseThrow(noAuthUserError());

    return clientService.findClientByClientIdAndAccount(clientId, account);

  }

  @Override
  public RegisteredClientDTO retrieveProtectedResource(String clientId,
      Authentication authentication) {
    authzChecks(authentication);

    return lookupProtectedResource(clientId, authentication)
      .map(converter::registrationResponseFromClient)
      .orElseThrow(clientNotFound(clientId));
  }

  @Validated(OnDynamicClientUpdate.class)
  @Override
  public RegisteredClientDTO updateClient(String clientId, RegisteredClientDTO request,
      Authentication authentication) throws ParseException {
    authzChecks(authentication);

    ClientDetailsEntity oldClient =
        lookupClient(clientId, authentication).orElseThrow(clientNotFound(clientId));

    checkUserUpdatingSuspendedClient(authentication, oldClient);
    checkAllowedGrantTypesOnUpdate(request, authentication, oldClient);
    cleanupRequestedScopesOnUpdate(request, authentication, oldClient);

    ClientDetailsEntity newClient = converter.entityFromRegistrationRequest(request);
    newClient.setId(oldClient.getId());
    if (ClientUtils.AUTH_METHODS_REQUIRING_SECRET.contains(newClient.getTokenEndpointAuthMethod())
        && Objects.isNull(oldClient.getClientSecret())) {
      // We should add a pop-up window to the UI with the new secret and hash the
      // client secret in db (the new secret is now available to the user only under
      // secret regeneration)
      newClient.setClientSecret(clientUtils.generateClientSecret());
    } else if (!ClientUtils.AUTH_METHODS_REQUIRING_SECRET
      .contains(newClient.getTokenEndpointAuthMethod())
        && !Objects.isNull(oldClient.getClientSecret())) {
      newClient.setClientSecret(null);
    } else {
      newClient.setClientSecret(oldClient.getClientSecret());
    }
    newClient.setAccessTokenValiditySeconds(oldClient.getAccessTokenValiditySeconds());
    newClient.setIdTokenValiditySeconds(oldClient.getIdTokenValiditySeconds());
    newClient.setRefreshTokenValiditySeconds(oldClient.getRefreshTokenValiditySeconds());
    newClient.setDeviceCodeValiditySeconds(oldClient.getDeviceCodeValiditySeconds());
    newClient.setDynamicallyRegistered(true);
    newClient.setAllowIntrospection(oldClient.isAllowIntrospection());
    newClient.setAuthorities(oldClient.getAuthorities());
    newClient.setCreatedAt(oldClient.getCreatedAt());
    newClient.setReuseRefreshToken(oldClient.isReuseRefreshToken());
    newClient.setActive(oldClient.isActive());

    // If user isn't admin upscoping doesn't change
    if (!accountUtils.isAdmin(authentication)) {
      newClient.setUpScopingEnabled(oldClient.isUpScopingEnabled());
    }

    if (registrationProperties.isAdminOnlyCustomScopes() && !accountUtils.isAdmin(authentication)) {
      removeCustomScopes(newClient);
    }

    ClientDetailsEntity savedClient = clientService.updateClient(newClient);

    eventPublisher.publishEvent(new ClientUpdatedEvent(this, savedClient));

    return converter.registrationResponseFromClient(savedClient);
  }

  @Validated(OnDynamicClientUpdate.class)
  @Override
  public RegisteredClientDTO updateProtectedResource(String clientId, RegisteredClientDTO request,
      Authentication authentication) throws ParseException {

    authzChecks(authentication);

    ClientDetailsEntity oldClient =
        lookupProtectedResource(clientId, authentication).orElseThrow(clientNotFound(clientId));

    checkUserUpdatingSuspendedClient(authentication, oldClient);
    cleanupRequestedScopesOnUpdate(request, authentication, oldClient);

    ClientDetailsEntity newClient = converter.entityFromRegistrationRequest(request);
    newClient.setId(oldClient.getId());
    newClient.setClientId(oldClient.getClientId());
    if (ClientUtils.AUTH_METHODS_REQUIRING_SECRET.contains(newClient.getTokenEndpointAuthMethod())
        && Objects.isNull(oldClient.getClientSecret())) {
      // Same as for client update
      newClient.setClientSecret(clientUtils.generateClientSecret());
    } else if (!ClientUtils.AUTH_METHODS_REQUIRING_SECRET
      .contains(newClient.getTokenEndpointAuthMethod())
        && !Objects.isNull(oldClient.getClientSecret())) {
      newClient.setClientSecret(null);
    } else {
      newClient.setClientSecret(oldClient.getClientSecret());
    }
    clientUtils.setupProtectedResourceDefaults(newClient);
    newClient.setActive(oldClient.isActive());

    if (registrationProperties.isAdminOnlyCustomScopes() && !accountUtils.isAdmin(authentication)) {
      removeCustomScopes(newClient);
    }

    ClientDetailsEntity savedClient = clientService.updateClient(newClient);

    eventPublisher.publishEvent(new ClientUpdatedEvent(this, savedClient));

    return converter.registrationResponseFromClient(savedClient);
  }

  @Override
  public void deleteClient(String clientId, Authentication authentication) {
    authzChecks(authentication);

    ClientDetailsEntity client =
        lookupClient(clientId, authentication).orElseThrow(clientNotFound(clientId));

    clientService.deleteClient(client);

    eventPublisher.publishEvent(new ClientRemovedEvent(this, client));
  }

  @Override
  public void deleteProtectedResource(String clientId, Authentication authentication) {
    authzChecks(authentication);

    ClientDetailsEntity client =
        lookupProtectedResource(clientId, authentication).orElseThrow(clientNotFound(clientId));

    clientService.deleteClient(client);

    eventPublisher.publishEvent(new ClientRemovedEvent(this, client));
  }

  @Override
  public RegisteredClientDTO redeemClient(@NotBlank String clientId,
      @NotBlank String registrationAccessToken, Authentication authentication) {
    authzChecks(authentication);

    if (!accountUtils.isRegisteredUser(authentication)) {
      throw new InvalidClientRegistrationRequest(NO_AUTH_USER_ERROR);
    }

    if (!registrationAccessTokenValueValidForClientId(clientId, registrationAccessToken)) {
      throw new InvalidClientRegistrationRequest(INVALID_ACCESS_TOKEN_ERROR);
    }

    ClientDetailsEntity client =
        clientService.findClientByClientId(clientId).orElseThrow(clientNotFound(clientId));

    final IamAccount account =
        accountUtils.getAuthenticatedUserAccount(authentication).orElseThrow(noAuthUserError());

    client = clientService.linkClientToAccount(client, account);

    eventPublisher.publishEvent(new AccountClientOwnerAssigned(this, account, client));

    return converter.registrationResponseFromClient(client);
  }

}
