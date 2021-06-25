/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2019
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
package it.infn.mw.iam.core.oauth.exchange;

import static it.infn.mw.iam.core.oauth.exchange.TokenExchangePdpResult.invalidScope;
import static it.infn.mw.iam.core.oauth.exchange.TokenExchangePdpResult.notApplicable;
import static it.infn.mw.iam.core.oauth.exchange.TokenExchangePdpResult.resultFromPolicy;
import static java.util.Comparator.comparing;

import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.stereotype.Service;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.collect.Lists;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcher;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcherRegistry;
import it.infn.mw.iam.persistence.model.IamTokenExchangePolicyEntity;
import it.infn.mw.iam.persistence.repository.IamTokenExchangePolicyRepository;

@Service
public class DefaultTokenExchangePdp implements TokenExchangePdp {
  public static final Logger LOG = LoggerFactory.getLogger(DefaultTokenExchangePdp.class);

  public static final String NOT_APPLICABLE_ERROR_TEMPLATE =
      "No applicable policies found for clients: %s -> %s";

  private final ScopeMatcherRegistry scopeMatcherRegistry;

  List<TokenExchangePolicy> policies = Lists.newArrayList();

  private final LoadingCache<TokenExchangePolicyCacheKey, Set<TokenExchangePolicy>> policyCache;

  @Autowired
  public DefaultTokenExchangePdp(IamProperties iamProperties, IamTokenExchangePolicyRepository repo,
      ScopeMatcherRegistry scopeMatcherRegistry) {
    this.scopeMatcherRegistry = scopeMatcherRegistry;
    final Long cacheExpireAfterWriteSecs =
        iamProperties.getTokenExchange().getExpirePolicyCacheAfterSeconds();

    LOG.debug("Token exchange policy cache entries expire after '{}' seconds since last update",
        cacheExpireAfterWriteSecs);

    this.policyCache = CacheBuilder.newBuilder()
      .expireAfterWrite(
          Duration.ofSeconds(cacheExpireAfterWriteSecs))
      .build(new TokenExchangePolicyCacheLoader(repo));
  }

  public Cache<TokenExchangePolicyCacheKey, Set<TokenExchangePolicy>> getPolicyCache() {
    return policyCache;
  }

  Set<TokenExchangePolicy> applicablePolicies(ClientDetails origin, ClientDetails destination) {
    return Optional
      .ofNullable(policyCache.getUnchecked(TokenExchangePolicyCacheKey.forClients(origin, destination)))
      .orElse(Collections.emptySet());
  }

  private TokenExchangePdpResult verifyScopes(TokenExchangePolicy p, TokenRequest request,
      ClientDetails origin, ClientDetails destination) {

    if (p.isDeny() || request.getScope().isEmpty()) {
      return resultFromPolicy(p);
    }

    // The requested scopes must be allowed for the origin client (destination is impersonating the
    // origin client)
    Set<ScopeMatcher> originClientMatchers = scopeMatcherRegistry.findMatchersForClient(origin);

    for (String scope : request.getScope()) {
      // Check requested scope is allowed by client configuration
      if (originClientMatchers.stream().noneMatch(m -> m.matches(scope))) {
        return invalidScope(p, scope, "scope not allowed by client configuration");
      }

      // Check requested scope is compliant with policies
      if (p.scopePolicies()
        .stream()
        .filter(m -> m.appliesToScope(scope))
        .anyMatch(m -> m.deniesScope(scope))) {
        return invalidScope(p, scope, "scope exchange not allowed by policy");
      }
    }

    return resultFromPolicy(p);
  }


  @Override
  public TokenExchangePdpResult validateTokenExchange(TokenRequest request, ClientDetails origin,
      ClientDetails destination) {

    return applicablePolicies(origin, destination).stream()
      .max(comparing(TokenExchangePolicy::rank).thenComparing(TokenExchangePolicy::getRule))
      .map(p -> verifyScopes(p, request, origin, destination))
      .orElse(notApplicable());
  }



  private static class TokenExchangePolicyCacheKey {

    private ClientDetails originClient;
    private ClientDetails destinationClient;

    private TokenExchangePolicyCacheKey() {

    }

    @Override
    public int hashCode() {
      return Objects.hash(destinationClient.getClientId(), originClient.getClientId());
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj)
        return true;
      if (obj == null)
        return false;
      if (getClass() != obj.getClass())
        return false;
      TokenExchangePolicyCacheKey other = (TokenExchangePolicyCacheKey) obj;
      return Objects.equals(destinationClient.getClientId(), other.destinationClient.getClientId())
          && Objects.equals(originClient.getClientId(), other.originClient.getClientId());
    }


    static TokenExchangePolicyCacheKey forClients(ClientDetails originClient, ClientDetails destinationClient) {
      TokenExchangePolicyCacheKey key = new TokenExchangePolicyCacheKey();
      key.originClient = originClient;
      key.destinationClient = destinationClient;
      return key;
    }

    @Override
    public String toString() {
      return "TEPCK[o=" + originClient.getClientId() + ", d="
          + destinationClient.getClientId() + "]";
    }
  }

  private static class TokenExchangePolicyCacheLoader
      extends CacheLoader<TokenExchangePolicyCacheKey, Set<TokenExchangePolicy>> {

    public static final Logger LOG = LoggerFactory.getLogger(TokenExchangePolicyCacheLoader.class);

    private final IamTokenExchangePolicyRepository repo;

    public TokenExchangePolicyCacheLoader(IamTokenExchangePolicyRepository repo) {
      this.repo = repo;
    }

    @Override
    public Set<TokenExchangePolicy> load(TokenExchangePolicyCacheKey key) throws Exception {

      LOG.debug("Loading token exchange policies for key: {}", key);

      List<TokenExchangePolicy> policies = Lists.newArrayList();

      for (IamTokenExchangePolicyEntity p : repo.findAll()) {
        policies.add(TokenExchangePolicy.builder().fromEntity(p).build());
      }

      return policies.stream()
        .filter(p -> p.appicableFor(key.originClient, key.destinationClient))
        .collect(Collectors.toSet());
    }

  }

  @Override
  public void clearPolicyCache() {
    getPolicyCache().invalidateAll();
  }
}
