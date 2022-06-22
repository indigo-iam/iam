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

import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2RequestValidator;
import org.springframework.security.oauth2.provider.TokenRequest;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;

@SuppressWarnings("deprecation")
public class ScopeMatcherOAuthRequestValidator implements OAuth2RequestValidator {

  public static final int DEFAULT_CACHE_SIZE = 10;

  public static final String ERROR_MSG_FMT = "Scope '%s' not allowed for client '%s'";

  private final ScopeMatcherRegistry registry;
  private final LoadingCache<ClientDetails, Set<ScopeMatcher>> scopeMatchersCache;

  public ScopeMatcherOAuthRequestValidator(ScopeMatcherRegistry matcherRegistry, int cacheSize) {
    this.registry = matcherRegistry;
    int cs = cacheSize < DEFAULT_CACHE_SIZE ? DEFAULT_CACHE_SIZE : cacheSize;
    scopeMatchersCache = CacheBuilder.newBuilder()
      .maximumSize(cs)
      .build(CacheLoader.from(registry::findMatchersForClient));
  }

  public ScopeMatcherOAuthRequestValidator(ScopeMatcherRegistry matcherRegistry) {
    this(matcherRegistry, DEFAULT_CACHE_SIZE);
  }

  private void validateScope(Set<String> requestedScopes, ClientDetails client) {

    Set<ScopeMatcher> scopeMatchers = scopeMatchersCache.getUnchecked(client);
    for (String s : requestedScopes) {
      if (scopeMatchers.stream().noneMatch(m -> m.matches(s))) {
        throw new InvalidScopeException(String.format(ERROR_MSG_FMT, s, client.getClientId()));
      }
    }
  }

  @Override
  public void validateScope(AuthorizationRequest authorizationRequest, ClientDetails client) {
    validateScope(authorizationRequest.getScope(), client);
  }

  @Override
  public void validateScope(TokenRequest tokenRequest, ClientDetails client){
    validateScope(tokenRequest.getScope(), client);
  }

  public void invalidateScope(ClientDetails client) {
    scopeMatchersCache.invalidate(client);
  }
}
