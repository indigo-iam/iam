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
package it.infn.mw.iam.core.oauth.scope;

import static java.util.stream.Collectors.toSet;

import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.mitre.oauth2.model.SystemScope;
import org.mitre.oauth2.service.SystemScopeService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import it.infn.mw.iam.audit.events.scope.ScopeCreatedEvent;
import it.infn.mw.iam.audit.events.scope.ScopeRemovedEvent;
import it.infn.mw.iam.audit.events.scope.ScopeUpdatedEvent;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcher;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcherRegistry;
import it.infn.mw.iam.persistence.repository.IamScopeRepository;

public class IamSystemScopeService implements SystemScopeService {

  public static final Set<String> RESERVED_SCOPE_PREFIXES = Set.of("iam", "registration", "scim");

  public static final Logger LOG = LoggerFactory.getLogger(IamSystemScopeService.class);

  public static final String ADMIN_READ_SCOPE = "iam:admin.read";
  public static final String ADMIN_WRITE_SCOPE = "iam:admin.write";

  public static final String REGISTRATION_READ_SCOPE = "registration:read";
  public static final String REGISTRATION_WRITE_SCOPE = "registration:write";

  public static final String SCIM_READ_SCOPE = "scim:read";
  public static final String SCIM_WRITE_SCOPE = "scim:write";

  public static final String REGISTRATION_TOKEN_SCOPE = "registration-token";
  public static final String RESOURCE_TOKEN_SCOPE = "resource-token";

  private final IamScopeRepository scopeRepository;
  private final ScopeMatcherRegistry scopeMatcherRegistry;
  private final ApplicationEventPublisher eventPublisher;

  public static final Set<String> RESERVED_VALUES =
      Set.of(REGISTRATION_TOKEN_SCOPE, RESOURCE_TOKEN_SCOPE);

  public static final Set<String> PROTECTED_SCOPES = Set.of(ADMIN_READ_SCOPE, ADMIN_WRITE_SCOPE,
      REGISTRATION_READ_SCOPE, REGISTRATION_WRITE_SCOPE, SCIM_READ_SCOPE, SCIM_WRITE_SCOPE);

  private Function<String, SystemScope> stringToSystemScope = scopeStr -> {
    if (scopeStr == null || scopeStr.isBlank()) {
      throw new IllegalArgumentException("Unable to convert from blank/null String to SystemScope");
    }
    Optional<SystemScope> scopeFromDatabase = getByValue(scopeStr);
    return scopeFromDatabase.isEmpty() ? new SystemScope(scopeStr) : scopeFromDatabase.get();
  };


  public IamSystemScopeService(IamScopeRepository scopeRepository,
      ScopeMatcherRegistry matcherRegistry, ApplicationEventPublisher eventPublisher) {
    this.scopeRepository = scopeRepository;
    this.scopeMatcherRegistry = matcherRegistry;
    this.eventPublisher = eventPublisher;
  }

  @Override
  public boolean scopesMatch(Set<String> allowedScopes, Set<String> requestedScopes) {

    Set<ScopeMatcher> allowedScopeMatchers =
        allowedScopes.stream().map(scopeMatcherRegistry::findMatcherForScope).collect(toSet());

    for (String rs : requestedScopes) {
      if (allowedScopeMatchers.stream().noneMatch(m -> m.matches(rs))) {
        return false;
      }
    }
    return true;
  }

  @Override
  public Set<SystemScope> getAllSorted() {
    return scopeRepository.findAll(Sort.by("value").ascending())
      .stream()
      .collect(Collectors.toCollection(LinkedHashSet::new));
  }

  @Override
  public Set<SystemScope> getDefaults() {
    return scopeRepository.findByIsDefaultScopeTrue().stream().collect(Collectors.toSet());
  }

  @Override
  public Set<SystemScope> getRestricted() {
    return scopeRepository.findByIsRestrictedTrue().stream().collect(Collectors.toSet());
  }

  @Override
  public Set<SystemScope> getUnrestricted() {
    return scopeRepository.findByIsRestrictedFalse().stream().collect(Collectors.toSet());
  }

  @Override
  public Optional<SystemScope> getById(Long id) {
    return scopeRepository.findById(id);
  }

  @Override
  public Optional<SystemScope> getByValue(String value) {
    if (!value.contains(":")) {
      return scopeRepository.findByValue(value);
    }
    String prefix = value.split(":")[0];
    Optional<SystemScope> scopeByPrefix = scopeRepository.findByValue(prefix);
    if (scopeByPrefix.isPresent()) {
      return scopeByPrefix;
    }
    return scopeRepository.findByValue(prefix + ":/");
  }

  @Override
  public void remove(Long id) {
    Optional<SystemScope> scope = scopeRepository.findById(id);
    if (scope.isEmpty()) {
      return;
    }
    if (isReserved(scope.get().getValue()) || isProtected(scope.get().getValue())) {
      LOG.error("Reserved and protected scopes like {} cannot be removed", scope.get().getValue());
      return;
    }
    scopeRepository.delete(scope.get());
    eventPublisher.publishEvent(new ScopeRemovedEvent(this, scope.get(),
        "Deleted scope with value " + scope.get().getValue()));
  }

  @Override
  public SystemScope create(SystemScope scope) {

    scope.setId(null);
    if (isReserved(scope.getValue())) {
      LOG.error("Invalid reserved scope value '{}'", scope.getValue());
      throw invalidScopeValue();
    }
    if (isProtected(scope.getValue())) {
      LOG.error("Invalid protected scope value '{}'", scope.getValue());
      throw invalidScopeValue();
    }
    if (scope.isStructured() && !scope.getValue().endsWith(":/")) {
      LOG.error("Structured scopes MUST end with ':/'");
      throw invalidScopeValue();
    }
    SystemScope createdScope = scopeRepository.saveAndFlush(scope);
    eventPublisher.publishEvent(new ScopeCreatedEvent(this, createdScope,
        "Scope '" + createdScope.getValue() + "' created."));
    return createdScope;
  }

  @Override
  public Set<SystemScope> fromStrings(Set<String> scopes) {

    if (scopes == null || scopes.isEmpty()) {
      return new LinkedHashSet<>();
    }
    return scopes.stream()
      .map(stringToSystemScope)
      .filter(Objects::nonNull)
      .collect(Collectors.toCollection(LinkedHashSet::new));
  }

  @Override
  public Set<SystemScope> removeRestrictedAndReservedScopes(Set<SystemScope> scopes) {
    return scopes.stream()
      .filter(s -> !s.isRestricted() && !isReserved(s.getValue()))
      .collect(Collectors.toSet());
  }

  @Override
  public boolean isReserved(String scope) {
    return RESERVED_VALUES.contains(scope);
  }

  @Override
  public boolean hasReserved(Set<String> scopes) {
    return scopes.stream().anyMatch(this::isReserved);
  }

  private ResponseStatusException invalidScopeValue() {
    return new ResponseStatusException(HttpStatus.BAD_REQUEST, "Scope value not valid");
  }

  private ResponseStatusException idNotFound() {
    return new ResponseStatusException(HttpStatus.NOT_FOUND, "Scope id not found");
  }

  @Override
  public boolean isProtected(String scope) {
    return PROTECTED_SCOPES.contains(scope)
        || RESERVED_SCOPE_PREFIXES.stream().anyMatch(scope::startsWith);
  }

  @Override
  public SystemScope update(SystemScope scope) {
    Optional<SystemScope> previousScope = scopeRepository.findById(scope.getId());
    if (previousScope.isEmpty()) {
      throw idNotFound();
    }
    if (isReserved(previousScope.get().getValue()) || isProtected(previousScope.get().getValue())) {
      LOG.error("Reserved and protected scopes like {} cannot be updated",
          previousScope.get().getValue());
      throw invalidScopeValue();
    }
    if (isReserved(scope.getValue()) || isProtected(scope.getValue())) {
      LOG.error("Reserved and protected scopes like {} cannot be updated", scope.getValue());
      throw invalidScopeValue();
    }
    SystemScope updatedScope = scopeRepository.saveAndFlush(scope);
    eventPublisher.publishEvent(new ScopeUpdatedEvent(this, updatedScope, previousScope.get(),
        "Scope with id " + updatedScope.getId() + " updated."));
    return updatedScope;
  }

}
