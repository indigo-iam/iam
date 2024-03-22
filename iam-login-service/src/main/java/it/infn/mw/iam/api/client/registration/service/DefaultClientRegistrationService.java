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
import java.time.Clock;
import java.time.Instant;
import java.util.EnumSet;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;

import javax.validation.constraints.NotBlank;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.service.SystemScopeService;
import org.mitre.openid.connect.service.OIDCTokenService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.stereotype.Service;
import org.springframework.validation.annotation.Validated;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.client.error.InvalidClientRegistrationRequest;
import it.infn.mw.iam.api.client.registration.validation.OnDynamicClientRegistration;
import it.infn.mw.iam.api.client.registration.validation.OnDynamicClientUpdate;
import it.infn.mw.iam.api.client.service.ClientConverter;
import it.infn.mw.iam.api.client.service.ClientDefaultsService;
import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.api.common.client.AuthorizationGrantType;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.audit.events.account.client.AccountClientOwnerAssigned;
import it.infn.mw.iam.audit.events.client.ClientRegistered;
import it.infn.mw.iam.audit.events.client.ClientRegistrationAccessTokenRotatedEvent;
import it.infn.mw.iam.audit.events.client.ClientRemovedEvent;
import it.infn.mw.iam.audit.events.client.ClientUpdatedEvent;
import it.infn.mw.iam.config.client_registration.ClientRegistrationProperties;
import it.infn.mw.iam.config.client_registration.ClientRegistrationProperties.ClientRegistrationAuthorizationPolicy;
import it.infn.mw.iam.core.IamTokenService;
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
      EnumSet.of(AuthorizationGrantType.PASSWORD, AuthorizationGrantType.TOKEN_EXCHANGE, AuthorizationGrantType.CLIENT_CREDENTIALS);

  private final Clock clock;
  private final ClientService clientService;
  private final AccountUtils accountUtils;
  private final ClientConverter converter;
  private final ClientDefaultsService defaultsService;
  private final OIDCTokenService clientTokenService;
  private final IamTokenService tokenService;
  private final SystemScopeService systemScopeService;
  private final ClientRegistrationProperties registrationProperties;
  private final ScopeMatcherRegistry scopeMatcherRegistry;
  private final ApplicationEventPublisher eventPublisher;


  public DefaultClientRegistrationService(Clock clock, ClientService clientService,
      AccountUtils accountUtils, ClientConverter converter, ClientDefaultsService defaultsService,
      OIDCTokenService clientTokenService, IamTokenService tokenService,
      SystemScopeService scopeService, ClientRegistrationProperties registrationProperties,
      ScopeMatcherRegistry scopeMatcherRegistry, ApplicationEventPublisher aep) {

    this.clock = clock;
    this.clientService = clientService;
    this.accountUtils = accountUtils;
    this.converter = converter;
    this.defaultsService = defaultsService;
    this.clientTokenService = clientTokenService;
    this.tokenService = tokenService;
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

    systemScopeService.getReserved().forEach(s -> request.getScope().remove(s.getValue()));

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

  private void cleanupRequestedScopes(ClientDetailsEntity entity, Authentication authentication) {

    if (entity.getScope().isEmpty()) {
      entity.getScope().addAll(systemScopeService.toStrings(systemScopeService.getDefaults()));
    } else {
      systemScopeService.getReserved().forEach(s -> entity.getScope().remove(s.getValue()));
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

  private boolean ratHasExpired(OAuth2AccessTokenEntity token) throws ParseException {
    final int defaultRatValiditySeconds = registrationProperties.getClientDefaults()
      .getDefaultRegistrationAccessTokenValiditySeconds();

    if (defaultRatValiditySeconds < 0) {
      return false;
    }

    Instant ratIssueTime = token.getJwt().getJWTClaimsSet().getIssueTime().toInstant();
    Instant ratExpirationTime = ratIssueTime.plusSeconds(defaultRatValiditySeconds);

    return clock.instant().isAfter(ratExpirationTime);
  }

  private boolean registrationAccessTokenValueValidForClientId(String clientId, String rat) {

    try {

      OAuth2AccessTokenEntity token = tokenService.readAccessToken(rat);

      var hasRegistrationScope =
          token.getScope().contains(SystemScopeService.REGISTRATION_TOKEN_SCOPE);

      var matchesClientId = token.getClient().getClientId().equals(clientId);

      var ratHasNotExpired = !ratHasExpired(token);

      return hasRegistrationScope && matchesClientId && ratHasNotExpired;

    } catch (Exception e) {
      return false;
    }
  }

  private Optional<String> maybeUpdateRegistrationAccessToken(ClientDetailsEntity client,
      Authentication auth) {

    if ((auth instanceof OAuth2Authentication oauth)
        && registrationAccessTokenAuthenticationValidForClientId(client.getClientId(), auth)) {

      OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) oauth.getDetails();
      OAuth2AccessTokenEntity token = tokenService.readAccessToken(details.getTokenValue());

      try {
        if (ratHasExpired(token)) {
          tokenService.revokeAccessToken(token);
          token = clientTokenService.createRegistrationAccessToken(client);
          tokenService.saveAccessToken(token);
          return Optional.of(token.getValue());
        } else {
          return Optional.empty();
        }
      } catch (ParseException e) {
        // if there's a problem in parsing the token, we consider it
        // expired and issue a new one
        tokenService.revokeAccessToken(token);
        token = clientTokenService.createRegistrationAccessToken(client);
        tokenService.saveAccessToken(token);
        return Optional.of(token.getValue());
      }
    }

    return Optional.empty();
  }

  @Validated(OnDynamicClientRegistration.class)
  @Override
  public RegisteredClientDTO registerClient(RegisteredClientDTO request,
      Authentication authentication) throws ParseException {

    authzChecks(authentication);

    ClientDetailsEntity client = converter.entityFromRegistrationRequest(request);
    defaultsService.setupClientDefaults(client);
    client.setDynamicallyRegistered(true);
    client.setActive(true);

    checkAllowedGrantTypes(request, authentication);
    cleanupRequestedScopes(client, authentication);

    client = clientService.saveNewClient(client);

    RegisteredClientDTO response = converter.registrationResponseFromClient(client);

    if (isAnonymous(authentication)) {

      OAuth2AccessTokenEntity ratEntity = clientTokenService.createRegistrationAccessToken(client);
      tokenService.saveAccessToken(ratEntity);
      response.setRegistrationAccessToken(ratEntity.getValue());

    } else {

      IamAccount account =
          accountUtils.getAuthenticatedUserAccount(authentication).orElseThrow(noAuthUserError());

      client.getContacts().add(account.getUserInfo().getEmail());

      clientService.linkClientToAccount(client, account);
    }

    eventPublisher.publishEvent(new ClientRegistered(this, client));

    return response;
  }

  private Optional<ClientDetailsEntity> lookupClient(String clientId,
      Authentication authentication) {

    if (isAnonymous(authentication)) {
      if (!registrationAccessTokenAuthenticationValidForClientId(clientId, authentication)) {
        throw new InvalidClientRegistrationRequest(INVALID_ACCESS_TOKEN_ERROR);
      }

      return clientService.findClientByClientId(clientId);
    } else {

      IamAccount account =
          accountUtils.getAuthenticatedUserAccount(authentication).orElseThrow(noAuthUserError());

      return clientService.findClientByClientIdAndAccount(clientId, account);
    }
  }

  @Override
  public RegisteredClientDTO retrieveClient(String clientId, Authentication authentication) {
    authzChecks(authentication);

    return lookupClient(clientId, authentication).map(converter::registrationResponseFromClient)
      .orElseThrow(clientNotFound(clientId));
  }


  @Validated(OnDynamicClientUpdate.class)
  @Override
  public RegisteredClientDTO updateClient(String clientId, RegisteredClientDTO request,
      Authentication authentication) throws ParseException {
    authzChecks(authentication);

    ClientDetailsEntity oldClient =
        lookupClient(clientId, authentication).orElseThrow(clientNotFound(clientId));

    checkAllowedGrantTypesOnUpdate(request, authentication, oldClient);
    cleanupRequestedScopesOnUpdate(request, authentication, oldClient);

    ClientDetailsEntity newClient = converter.entityFromRegistrationRequest(request);
    newClient.setId(oldClient.getId());
    newClient.setClientSecret(oldClient.getClientSecret());
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

    ClientDetailsEntity savedClient = clientService.updateClient(newClient);

    eventPublisher.publishEvent(new ClientUpdatedEvent(this, savedClient));

    RegisteredClientDTO response = converter.registrationResponseFromClient(savedClient);

    maybeUpdateRegistrationAccessToken(savedClient, authentication).ifPresent(t -> {
      eventPublisher.publishEvent(new ClientRegistrationAccessTokenRotatedEvent(this, savedClient));
      response.setRegistrationAccessToken(t);
    });

    return response;
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
