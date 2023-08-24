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

import java.util.Set;

import org.mitre.oauth2.model.SystemScope;
import org.mitre.oauth2.repository.SystemScopeRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.oauth2.provider.ClientDetails;

import com.google.common.collect.Sets;

@SuppressWarnings("deprecation")
public class DefaultScopeMatcherRegistry implements ScopeMatcherRegistry {

  @Autowired
  private SystemScopeRepository scopeRepo;

  public static final String SCOPE_CACHE_KEY = "scope-matcher";

  private final Set<ScopeMatcher> customMatchers;

  public DefaultScopeMatcherRegistry(Set<ScopeMatcher> customMatchers) {
    this.customMatchers = customMatchers;
  }

  @Override
  @Cacheable(value = SCOPE_CACHE_KEY, key = "{#client?.id}")
  public Set<ScopeMatcher> findMatchersForClient(ClientDetails client) {
    Set<ScopeMatcher> result = Sets.newHashSet();

    for (String s : client.getScope()) {
      result.add(findMatcherForScope(s));

    }

    return result;
  }

  @Override
  public ScopeMatcher findMatcherForScope(String scope) {

    Set<SystemScope> systemScopes = scopeRepo.getAll();

      if (!systemScopes.toString().contains(scope)) {
        return StringEqualsScopeMatcher.stringEqualsMatcher(scope);
      } else {
        return customMatchers.stream()
          .filter(m -> m.matches(scope))
          .findFirst()
          .orElse(StringEqualsScopeMatcher.stringEqualsMatcher(scope));
      }
  }
}
