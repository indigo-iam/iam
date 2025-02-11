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

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static java.util.function.Predicate.not;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toSet;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;

import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcher;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcherRegistry;
import it.infn.mw.iam.persistence.model.SystemScope;
import it.infn.mw.iam.persistence.repository.SystemScopeRepository;

public class IamSystemScopeService implements SystemScopeService {

  public static final String REGISTRATION_TOKEN_SCOPE = "registration-token";
  public static final String RESOURCE_TOKEN_SCOPE = "resource-token";
  public static final String OFFLINE_ACCESS_SCOPE = "offline_access";
  public static final String OPENID_SCOPE = "openid";
  public static final String UMA_PROTECTION_SCOPE = "uma_protection";
  public static final String UMA_AUTHORIZATION_SCOPE = "uma_authorization";

  public static final Set<String> RESERVED_SCOPES =
      Set.of(REGISTRATION_TOKEN_SCOPE, RESOURCE_TOKEN_SCOPE);

  public static final Set<String> RESERVED_SCOPE_PREFIXES =
      Set.of("iam:", "scim:", "registration:");

  final SystemScopeRepository scopeRepository;
  final ScopeMatcherRegistry scopeMatcherRegistry;

  public IamSystemScopeService(SystemScopeRepository scopeRepository,
      ScopeMatcherRegistry matcherRegistry) {
    this.scopeRepository = scopeRepository;
    this.scopeMatcherRegistry = matcherRegistry;
  } 

  @Override
  public List<SystemScope> getAll() {
    return scopeRepository.findAllOrderByIdAsc();
  }

  @Override
  public List<SystemScope> getDefaults() {
    return scopeRepository.findByDefaultScopeTrueOrderByIdAsc();

  }

  @Override
  public List<SystemScope> getReserved() {
    return getAll().stream().filter(isReserved).collect(toList());
  }

  /**
   * Get all the registered scopes that are restricted.
   * 
   * @return
   */
  @Override
  public List<SystemScope> getRestricted() {
    return scopeRepository.findByRestrictedTrueOrderByIdAsc();
  }

  /**
   * Get all the registered scopes that aren't restricted.
   * 
   * @return
   */
  @Override
  public List<SystemScope> getUnrestricted() {
    return scopeRepository.findByRestrictedFalseOrderByIdAsc();
  }

  @Override
  public Optional<SystemScope> getById(Long id) {
    return scopeRepository.findById(id);
  }

  @Override
  public Optional<SystemScope> getByValue(String value) {
    return scopeRepository.findByValue(value);
  }

  @Override
  public void remove(SystemScope scope) {
    scopeRepository.delete(scope);
  }

  @Override
  public SystemScope save(SystemScope scope) {
    checkNotNull(scope, "Provided scope is null");
    checkArgument(!isReserved.test(scope), "You cannot override a reserved scope");
    checkArgument(!scope.getValue().matches("(iam:|scim:|registration:).*"), "You cannot insert a scope that starts with a reserved prefix such as 'iam:'");
    return scopeRepository.save(scope);
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

  private Predicate<SystemScope> isRestricted = new Predicate<SystemScope>() {
    @Override
    public boolean test(SystemScope s) {
      return (s != null && s.isRestricted());
    }
  };

  private Predicate<SystemScope> isReserved = new Predicate<SystemScope>() {
    @Override
    public boolean test(SystemScope s) {
      return (s != null && RESERVED_SCOPES.contains(s.getValue()));
    }
  };

  @Override
  public List<SystemScope> getAllNoRestrictedOrReserved() {
    return getAllNoReserved().stream().filter(not(isRestricted)).collect(toList());
  }

  @Override
  public List<SystemScope> getAllNoReserved() {
    return getAll().stream().filter(not(isReserved)).collect(toList());
  }

}
