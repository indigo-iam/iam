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
package it.infn.mw.iam.core.oauth.exchange;

import static it.infn.mw.iam.core.oauth.exchange.TokenExchangePdpResult.fromPolicy;
import static it.infn.mw.iam.core.oauth.exchange.TokenExchangePdpResult.invalidScope;
import static it.infn.mw.iam.core.oauth.exchange.TokenExchangePdpResult.notApplicable;
import static java.util.Comparator.comparing;

import java.util.List;
import java.util.Set;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.stereotype.Service;

import com.google.common.collect.Lists;

import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcher;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcherRegistry;
import it.infn.mw.iam.persistence.model.IamTokenExchangePolicyEntity;
import it.infn.mw.iam.persistence.repository.IamTokenExchangePolicyRepository;

@SuppressWarnings("deprecation")
@Service
public class DefaultTokenExchangePdp implements TokenExchangePdp, InitializingBean {

  public static final Logger LOG = LoggerFactory.getLogger(DefaultTokenExchangePdp.class);

  public static final String NOT_APPLICABLE_ERROR_TEMPLATE =
      "No applicable policies found for clients: %s -> %s";

  private final IamTokenExchangePolicyRepository repo;

  private final ScopeMatcherRegistry scopeMatcherRegistry;

  private List<TokenExchangePolicy> policies = Lists.newArrayList();

  private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
  private final ReentrantReadWriteLock.ReadLock readLock = lock.readLock();
  private final ReentrantReadWriteLock.WriteLock writeLock = lock.writeLock();

  @Autowired
  public DefaultTokenExchangePdp(IamTokenExchangePolicyRepository repo,
      ScopeMatcherRegistry scopeMatcherRegistry) {
    this.repo = repo;
    this.scopeMatcherRegistry = scopeMatcherRegistry;
  }

  Set<TokenExchangePolicy> applicablePolicies(ClientDetails origin, ClientDetails destination) {
    return policies.stream()
      .filter(p -> p.appicableFor(origin, destination))
      .collect(Collectors.toSet());
  }

  /**
   * In an exchange of scopes between the origin and destination client, the destination client is
   * the client that issued the token request. The scope verification at this stage checks that the
   * requested scopes are allowed by the origin client configuration, as the destination client is
   * impersonating the origin client.
   * 
   * After this checks, the scope policies linked to the exchange policy are applied for each
   * requested scope. If there's a policy that does not allow one of the requested scope, an
   * invalidScope result is returned providing detail on which scope is not allowed by the policy.
   * 
   * Checks on whether the requested scopes are also allowed by the destination client configuration
   * are implemented elsewhere in the chain (e.g., in the token exchange granter), and not
   * replicated here
   * 
   * @param p the policy for which scope policies should be applied
   * @param request the token request
   * @param origin, the origin client
   * @param destination the destination client
   * @return a decision result
   */
  private TokenExchangePdpResult verifyScopes(TokenExchangePolicy p, TokenRequest request,
      ClientDetails origin, ClientDetails destination) {

    if (p.isDeny() || request.getScope().isEmpty()) {
      return fromPolicy(p);
    }

    // The requested scopes must be allowed by the origin client (destination is impersonating the
    // origin client)
    Set<ScopeMatcher> originClientMatchers = scopeMatcherRegistry.findMatchersForClient(origin);

    for (String scope : request.getScope()) {
      // Check requested scope is permitted by client configuration
      if (originClientMatchers.stream().noneMatch(m -> m.matches(scope))) {
        return invalidScope(p, scope, "scope not allowed by origin client configuration");
      }

      // Check requested scope is compliant with policies
      if (p.scopePolicies()
        .stream()
        .filter(m -> m.appliesToScope(scope))
        .anyMatch(m -> m.deniesScope(scope))) {
        return invalidScope(p, scope, "scope exchange not allowed by policy");
      }
    }

    return fromPolicy(p);
  }



  @Override
  public TokenExchangePdpResult validateTokenExchange(TokenRequest request, ClientDetails origin,
      ClientDetails destination) {

    try {
      readLock.lock();
      return applicablePolicies(origin, destination).stream()
        .max(comparing(TokenExchangePolicy::rank).thenComparing(TokenExchangePolicy::getRule))
        .map(p -> verifyScopes(p, request, origin, destination))
        .orElse(notApplicable());
    } finally {
      readLock.unlock();
    }
  }

  @Override
  public void reloadPolicies() {

    try {
      LOG.debug("Token exchange policy reload started");
      writeLock.lock();
      policies.clear();

      for (IamTokenExchangePolicyEntity p : repo.findAll()) {
        policies.add(TokenExchangePolicy.builder().fromEntity(p).build());
      }

    } finally {
      writeLock.unlock();
      LOG.debug("Token exchange policy reload done");
    }
  }

  @Override
  public void afterPropertiesSet() throws Exception {
    reloadPolicies();
  }

}
