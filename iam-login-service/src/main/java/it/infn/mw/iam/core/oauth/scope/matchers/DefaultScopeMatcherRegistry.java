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

import static com.google.common.base.Preconditions.checkArgument;
import static java.util.Objects.nonNull;

import java.util.Set;

import org.springframework.security.oauth2.provider.ClientDetails;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.collect.Sets;

@SuppressWarnings("deprecation")
public class DefaultScopeMatcherRegistry implements ScopeMatcherRegistry {

  public static final int DEFAULT_CACHE_SIZE = 10;

  private final Set<ScopeMatcher> customMatchers;

  private final LoadingCache<String, ScopeMatcher> plainMatchersCache;

  public DefaultScopeMatcherRegistry(Set<ScopeMatcher> customMatchers) {
    this(customMatchers, DEFAULT_CACHE_SIZE);
  }

  public DefaultScopeMatcherRegistry(Set<ScopeMatcher> customMatchers, int plainMatchersCacheSize) {
    checkArgument(nonNull(customMatchers), "customMatchers must be non-null");
    int cacheSize =
        (plainMatchersCacheSize < DEFAULT_CACHE_SIZE ? DEFAULT_CACHE_SIZE : plainMatchersCacheSize);
    plainMatchersCache =
        CacheBuilder.newBuilder().maximumSize(cacheSize).build(CacheLoader.from(StringEqualsScopeMatcher::stringEqualsMatcher));
    this.customMatchers = customMatchers;
  }

  @Override
  public Set<ScopeMatcher> findMatchersForClient(ClientDetails client) {
    Set<ScopeMatcher> result = Sets.newHashSet();

    for (String s : client.getScope()) {
      result.add(findMatcherForScope(s));
    }

    return result;
  }

  @Override
  public ScopeMatcher findMatcherForScope(String scope) {
    return customMatchers.stream()
      .filter(m -> m.matches(scope))
      .findFirst()
      .orElse(plainMatchersCache.getUnchecked(scope));
  }

}
