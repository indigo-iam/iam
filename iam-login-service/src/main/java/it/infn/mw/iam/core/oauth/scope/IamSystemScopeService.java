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
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.mitre.oauth2.model.SystemScope;
import org.mitre.oauth2.service.SystemScopeService;

import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcher;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcherRegistry;
import it.infn.mw.iam.persistence.repository.IamScopeRepository;

public class IamSystemScopeService implements SystemScopeService {

  private final IamScopeRepository scopeRepository;
  private final ScopeMatcherRegistry scopeMatcherRegistry;

  private static final Set<String> RESERVED_VALUES = Set.of("registration-token", "resource-token");

  private Function<String, SystemScope> stringToSystemScope = scopeStr -> {
    if (scopeStr == null || scopeStr.isBlank()) {
      return null;
    }
    SystemScope scopeFromDatabase = getByValue(scopeStr);
    return scopeFromDatabase == null ? new SystemScope(scopeStr) : scopeFromDatabase;
  };

  private Function<SystemScope, String> systemScopeToString = scope -> {
    return scope == null ? null : scope.getValue();
  };

  public IamSystemScopeService(IamScopeRepository scopeRepository,
      ScopeMatcherRegistry matcherRegistry) {
    this.scopeRepository = scopeRepository;
    this.scopeMatcherRegistry = matcherRegistry;
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
    return scopeRepository.findAll().stream().collect(Collectors.toSet());
  }

  @Override
  public Set<SystemScope> getDefaults() {
    return scopeRepository.findByDefaultScopeTrue().stream().collect(Collectors.toSet());
  }

  @Override
  public Set<SystemScope> getReserved() {
    return scopeRepository.findReservedScopes().stream().collect(Collectors.toSet());
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
  public SystemScope getById(Long id) {
    return scopeRepository.findById(id).orElse(null);
  }

  @Override
  public SystemScope getByValue(String value) {
    return scopeRepository.findByValue(value).stream().findFirst().orElse(null);
  }

  @Override
  public void remove(SystemScope scope) {
    scopeRepository.delete(scope);
  }

  @Override
  public SystemScope save(SystemScope scope) {
    if (RESERVED_VALUES.contains(scope.getValue())) {
      return null;
    }
    return scopeRepository.save(scope);
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
  public Set<String> toStrings(Set<SystemScope> scopes) {

    if (scopes == null || scopes.isEmpty()) {
      return new LinkedHashSet<>();
    }
    return scopes.stream()
      .map(systemScopeToString)
      .filter(Objects::nonNull)
      .collect(Collectors.toCollection(LinkedHashSet::new));
  }

  @Override
  public Set<SystemScope> removeRestrictedAndReservedScopes(Set<SystemScope> scopes) {
    return scopes.stream().filter(s -> !s.isRestricted() && !isReserved(s)).collect(Collectors.toSet());
  }

  @Override
  public Set<SystemScope> removeReservedScopes(Set<SystemScope> scopes) {
    return scopes.stream().filter(s -> !isReserved(s)).collect(Collectors.toSet());
  }

  private boolean isReserved(SystemScope scope) {
    return RESERVED_VALUES.contains(scope.getValue());
  }

}
