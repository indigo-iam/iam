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
package it.infn.mw.iam.core.oauth.scope.matchers;

import java.util.HashSet;
import java.util.Set;

import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.oauth2.provider.ClientDetails;

import it.infn.mw.iam.persistence.repository.IamScopeRepository;

@SuppressWarnings("deprecation")
public class DefaultScopeMatcherRegistry implements ScopeMatcherRegistry {

  public static final String SCOPE_CACHE_KEY = "scope-matcher";

  private final Set<ScopeMatcher> customMatchers;
  private final IamScopeRepository scopeRepository;

  public DefaultScopeMatcherRegistry(Set<ScopeMatcher> customMatchers,
      IamScopeRepository scopeRepository) {
    this.customMatchers = customMatchers;
    this.scopeRepository = scopeRepository;
  }

  @Override
  @Cacheable(value = SCOPE_CACHE_KEY, key = "{#client?.id}")
  public Set<ScopeMatcher> findMatchersForClient(ClientDetails client) {

    Set<ScopeMatcher> result = new HashSet<>();
    for (String s : client.getScope()) {
      result.add(findMatcherForScope(s));
    }
    return result;
  }

  @Override
  public ScopeMatcher findMatcherForScope(String scope) {

    // Search for RegExp custom matchers
    for (ScopeMatcher matcher : customMatchers) {
      if (matcher instanceof RegexpScopeMatcher && matcher.matches(scope)) {
        return matcher;
      }
    }
    try {
      return scopeRepository.findByValue(scope)
        .map(dbScope -> dbScope.isStructured() ? StructuredPathScopeMatcher.fromString(scope)
            : StringEqualsScopeMatcher.stringEqualsMatcher(scope))
        .orElseGet(() -> StructuredPathScopeMatcher.fromString(scope));

    } catch (Exception e) {
      return StringEqualsScopeMatcher.stringEqualsMatcher(scope);
    }
  }
}
