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
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;

import com.google.common.base.Function;
import com.google.common.base.Predicate;
import com.google.common.base.Predicates;
import com.google.common.base.Strings;
import com.google.common.collect.Collections2;
import com.google.common.collect.Sets;

import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcher;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcherRegistry;
import it.infn.mw.iam.persistence.model.SystemScope;
import it.infn.mw.iam.persistence.repository.IamSystemScopeRepository;

@Service
public class IamSystemScopeService implements SystemScopeService {

  private final IamSystemScopeRepository systemScopeRepo;
  private final ScopeMatcherRegistry scopeMatcherRegistry;

  public IamSystemScopeService(IamSystemScopeRepository systemScopeRepo,
      ScopeMatcherRegistry matcherRegistry) {
    this.systemScopeRepo = systemScopeRepo;
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

  private Predicate<SystemScope> isDefault = new Predicate<SystemScope>() {
    @Override
    public boolean apply(SystemScope input) {
      return (input != null && input.isDefaultScope());
    }
  };

  private Predicate<SystemScope> isRestricted = new Predicate<SystemScope>() {
    @Override
    public boolean apply(SystemScope input) {
      return (input != null && input.isRestricted());
    }
  };

  private Predicate<SystemScope> isReserved = new Predicate<SystemScope>() {
    @Override
    public boolean apply(SystemScope input) {
      return (input != null && getReserved().contains(input));
    }
  };

  private Function<String, SystemScope> stringToSystemScope = new Function<String, SystemScope>() {
    @Override
    public SystemScope apply(String input) {
      if (Strings.isNullOrEmpty(input)) {
        return null;
      } else {
        // get the real scope if it's available
        SystemScope s = getByValue(input);
        if (s == null) {
          // make a fake one otherwise
          s = new SystemScope(input);
        }

        return s;
      }
    }
  };

  private Function<SystemScope, String> systemScopeToString = new Function<SystemScope, String>() {
    @Override
    public String apply(SystemScope input) {
      if (input == null) {
        return null;
      } else {
        return input.getValue();
      }
    }
  };

  @Override
  public Set<SystemScope> getAll() {
    return systemScopeRepo.findAll().stream().collect(Collectors.toSet());
  }

  @Override
  public SystemScope getById(Long id) {
    return systemScopeRepo.findById(id).orElse(null);
  }

  @Override
  public SystemScope getByValue(String value) {
    return systemScopeRepo.findByValue(value).orElse(null);
  }

  @Override
  public void remove(SystemScope scope) {
    systemScopeRepo.delete(scope);
  }

  @Override
  public SystemScope save(SystemScope scope) {
    if (!isReserved.apply(scope)) {
      return systemScopeRepo.save(scope);
    }
    return null;
  }

  @Override
  public Set<SystemScope> fromStrings(Set<String> scope) {
    if (scope == null) {
      return null;
    }
    return new LinkedHashSet<>(Collections2
      .filter(Collections2.transform(scope, stringToSystemScope), Predicates.notNull()));
  }

  @Override
  public Set<String> toStrings(Set<SystemScope> scope) {
    if (scope == null) {
      return null;
    }
    return new LinkedHashSet<>(Collections2
      .filter(Collections2.transform(scope, systemScopeToString), Predicates.notNull()));
  }

  @Override
  public Set<SystemScope> getDefaults() {
    return Sets.filter(getAll(), isDefault);
  }


  @Override
  public Set<SystemScope> getReserved() {
    return reservedScopes;
  }

  @Override
  public Set<SystemScope> getRestricted() {
    return Sets.filter(getAll(), isRestricted);
  }

  @Override
  public Set<SystemScope> getUnrestricted() {
    return Sets.filter(getAll(), Predicates.not(isRestricted));
  }

  @Override
  public Set<SystemScope> removeRestrictedAndReservedScopes(Set<SystemScope> scopes) {
    return Sets.filter(scopes, Predicates.not(Predicates.or(isRestricted, isReserved)));
  }

  @Override
  public Set<SystemScope> removeReservedScopes(Set<SystemScope> scopes) {
    return Sets.filter(scopes, Predicates.not(isReserved));
  }

}
