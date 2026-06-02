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
import java.util.stream.Collectors;

import org.mitre.oauth2.model.SystemScope;
import org.mitre.oauth2.service.SystemScopeService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import it.infn.mw.iam.audit.events.scope.ScopeCreatedEvent;
import it.infn.mw.iam.audit.events.scope.ScopeRemovedEvent;
import it.infn.mw.iam.audit.events.scope.ScopeUpdatedEvent;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcher;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcherRegistry;
import it.infn.mw.iam.persistence.repository.IamScopeRepository;

@SuppressWarnings("deprecation")
@Service
public class IamSystemScopeService implements SystemScopeService {

  public static final Logger LOG = LoggerFactory.getLogger(IamSystemScopeService.class);

  public static final String ADMIN_READ_SCOPE = "iam:admin.read";
  public static final String ADMIN_WRITE_SCOPE = "iam:admin.write";

  public static final String REGISTRATION_READ_SCOPE = "registration:read";
  public static final String REGISTRATION_WRITE_SCOPE = "registration:write";

  public static final String SCIM_READ_SCOPE = "scim:read";
  public static final String SCIM_WRITE_SCOPE = "scim:write";

  public static final Set<String> RESERVED_VALUES =
      Set.of(REGISTRATION_TOKEN_SCOPE, RESOURCE_TOKEN_SCOPE);

  public static final Set<String> PROTECTED_SCOPES = Set.of(ADMIN_READ_SCOPE, ADMIN_WRITE_SCOPE,
      REGISTRATION_READ_SCOPE, REGISTRATION_WRITE_SCOPE, SCIM_READ_SCOPE, SCIM_WRITE_SCOPE);

  private final IamScopeRepository scopeRepository;
  private final ScopeMatcherRegistry scopeMatcherRegistry;
  private final ApplicationEventPublisher eventPublisher;

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
  public Set<SystemScope> getAll() {
    return getAllSorted();
  }

  @Override
  public Set<SystemScope> getDefaults() {
    return scopeRepository.findByDefaultScopeTrue().stream().collect(Collectors.toSet());
  }

  @Override
  public Set<SystemScope> getRestricted() {
    return scopeRepository.findByRestrictedTrue().stream().collect(Collectors.toSet());
  }

  @Override
  public Set<SystemScope> getUnrestricted() {
    return scopeRepository.findByRestrictedFalse().stream().collect(Collectors.toSet());
  }

  @Override
  public SystemScope getByValue(String value) {
    return scopeRepository.findByValue(value).orElse(null);
  }

  @Override
  public void remove(SystemScope entity) {

    if (isReserved(entity.getValue()) || isProtected(entity.getValue())) {
      LOG.error("Reserved and protected scopes like {} cannot be removed", entity.getValue());
      throw new InvalidRequestException("Invalid reserved/protected scope");
    }
    scopeRepository.delete(entity);
    eventPublisher.publishEvent(new ScopeRemovedEvent(this, entity, "Deleted scope."));
  }

  @Override
  public Set<SystemScope> fromStrings(Set<String> scopes) {
    if (scopes == null || scopes.isEmpty()) {
      return new LinkedHashSet<>();
    }
    return scopes.stream().map(scope -> {
      SystemScope found = getByValue(scope);
      if (found == null) {
        return new SystemScope(scope);
      }
      return found;
    }).collect(Collectors.toCollection(LinkedHashSet::new));
  }

  @Override
  public Set<String> toStrings(Set<SystemScope> scopes) {
    if (scopes == null || scopes.isEmpty()) {
      return new LinkedHashSet<>();
    }
    return scopes.stream()
      .map(SystemScope::getValue)
      .filter(Objects::nonNull)
      .collect(Collectors.toCollection(LinkedHashSet::new));
  }

  @Override
  public SystemScope create(SystemScope entity) {

    entity.setId(null);
    scopeValueValidation(entity);
    SystemScope createdScope = scopeRepository.saveAndFlush(entity);
    eventPublisher.publishEvent(new ScopeCreatedEvent(this, createdScope, "New scope created."));
    return createdScope;
  }

  @Override
  public SystemScope update(SystemScope entity) {

    Optional<SystemScope> previousScope = get(entity.getId());
    if (previousScope.isEmpty()) {
      throw idNotFound();
    }
    scopeValueValidation(previousScope.get());
    scopeValueValidation(entity);
    SystemScope updatedScope = scopeRepository.saveAndFlush(entity);
    eventPublisher.publishEvent(
        new ScopeUpdatedEvent(this, updatedScope, previousScope.get(), "Scope updated."));
    return updatedScope;
  }

  @Override
  public Optional<SystemScope> get(Long id) {
    return scopeRepository.findById(id);
  }

  @Override
  public Set<SystemScope> getAllSorted() {
    return scopeRepository.findAll(Sort.by("value").ascending())
      .stream()
      .collect(Collectors.toCollection(LinkedHashSet::new));
  }

  protected void scopeValueValidation(SystemScope scope) {

    if (isReserved(scope.getValue())) {
      LOG.error("Invalid reserved scope value '{}'", scope.getValue());
      throw new InvalidRequestException("Invalid reserved scope");
    }
    if (isProtected(scope.getValue())) {
      LOG.error("Invalid protected scope value '{}'", scope.getValue());
      throw new InvalidRequestException("Invalid protected scope");
    }
  }

  protected boolean isReserved(String scope) {
    return RESERVED_VALUES.contains(scope);
  }

  public boolean isProtected(String scope) {
    return PROTECTED_SCOPES.contains(scope);
  }

  protected ResponseStatusException invalidScopeValue() {
    return new ResponseStatusException(HttpStatus.BAD_REQUEST, "Scope value not valid");
  }

  protected ResponseStatusException idNotFound() {
    return new ResponseStatusException(HttpStatus.NOT_FOUND, "Scope id not found");
  }
}
