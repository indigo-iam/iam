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
package it.infn.mw.iam.core.oauth.scope.pdp;

import static it.infn.mw.iam.core.oauth.scope.matchers.RegexpScopeMatcher.regexpMatcher;
import static it.infn.mw.iam.persistence.model.IamScopePolicy.MatchingPolicy.EQ;
import static it.infn.mw.iam.persistence.model.IamScopePolicy.MatchingPolicy.PATH;
import static it.infn.mw.iam.persistence.model.IamScopePolicy.MatchingPolicy.REGEXP;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;

import it.infn.mw.iam.api.scim.exception.IllegalArgumentException;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcher;
import it.infn.mw.iam.core.oauth.scope.matchers.StructuredPathScopeMatcher;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAccountGroupMembership;
import it.infn.mw.iam.persistence.model.IamScopePolicy;
import it.infn.mw.iam.persistence.repository.IamScopePolicyRepository;

@Component
public class DefaultScopePolicyPDP implements ScopePolicyPDP {

  public static final Logger LOG = LoggerFactory.getLogger(DefaultScopePolicyPDP.class);
  
  private Cache<String, ScopeMatcher> matchersCache =
      CacheBuilder.newBuilder().maximumSize(30).build();

  public static class DecisionContext {

    public static final Logger LOG = LoggerFactory.getLogger(DecisionContext.class);

    enum ScopeStatus {
      PERMIT,
      DENY,
      UNPROCESSED
    }

    private final Map<String, ScopeStatus> scopeStatus = Maps.newHashMap();
    private final Cache<String, ScopeMatcher> matchersCache;

    public DecisionContext(Cache<String, ScopeMatcher> matchersCache, Set<String> requestedScopes) {
      LOG.debug("Decision context created for scopes '{}'", requestedScopes);
      requestedScopes.forEach(s -> scopeStatus.put(s, ScopeStatus.UNPROCESSED));
      this.matchersCache = matchersCache;
    }

    protected void permitScope(String scope) {
      if (!scopeStatus.get(scope).equals(ScopeStatus.DENY)) {
        scopeStatus.put(scope, ScopeStatus.PERMIT);
      } else {
        LOG.debug("Permit on scope {} ignored. Former DENY overrides", scope);
      }
    }

    protected void denyScope(String scope) {
      scopeStatus.put(scope, ScopeStatus.DENY);
    }

    protected boolean entryIsUnprocessed(Map.Entry<String, ScopeStatus> e) {
      return e.getValue().equals(ScopeStatus.UNPROCESSED);
    }

    protected boolean entryIsProcessed(Map.Entry<String, ScopeStatus> e) {
      return !e.getValue().equals(ScopeStatus.UNPROCESSED);
    }
    
    protected boolean policyApplicableToScope(IamScopePolicy p, String scope) {
      if (p.getScopes().isEmpty()) {
        return true;
      }
      if (EQ.equals(p.getMatchingPolicy())) {
        return p.getScopes().contains(scope);
      } else if (REGEXP.equals(p.getMatchingPolicy())) {
        boolean foundMatch = false;
        for (String ps : p.getScopes()) {
          try {
            ScopeMatcher m = matchersCache.get(ps, () -> regexpMatcher(ps));
            if (m.matches(scope)) {
              foundMatch = true;
            }
          } catch (ExecutionException e) {
            throw new IllegalArgumentException(e.getMessage());
          }
        }
        return foundMatch;
      } else if (PATH.equals(p.getMatchingPolicy())) {
        boolean foundMatch = false;
        for (String ps : p.getScopes()) {
          ScopeMatcher m;
          try {
            m = matchersCache.get(ps, () -> StructuredPathScopeMatcher.fromString(ps));
            if (m.matches(scope)) {
              foundMatch = true;
            }
          } catch (ExecutionException e) {
            throw new IllegalArgumentException(e.getMessage());
          }
        }
        return foundMatch;
      } else {
        throw new IllegalArgumentException(
            "Unknown scope policy matching policy: " + p.getMatchingPolicy());
      }
    }

    protected void applyScopePolicy(String scope, IamScopePolicy p, IamAccount a) {
      LOG.debug("Evaluating {} policy #{} ('{}') against scope '{}' for account '{}'",
          p.getPolicyType(), p.getId(), p.getDescription(), scope, a.getUsername());

      if (!policyApplicableToScope(p, scope)) {
        LOG.debug("{} policy #{} ('{}') NOT APPLICABLE to scope '{}' for account '{}'",
            p.getPolicyType(), p.getId(), p.getDescription(), scope, a.getUsername());
        return;
      }

      if (p.isPermit()) {
        LOG.debug("{} policy #{} ('{}') PERMITS scope '{}' for account '{}'", p.getPolicyType(),
            p.getId(), p.getDescription(), scope, a.getUsername());
        permitScope(scope);

      } else {
        LOG.debug("{} policy #{} ('{}') DENIES scope '{}' for account '{}'", p.getPolicyType(),
            p.getId(), p.getDescription(), scope, a.getUsername());
        denyScope(scope);
      }
    }

    public void applyPolicy(IamScopePolicy p, IamAccount a) {
      scopeStatus.keySet().forEach(s -> applyScopePolicy(s, p, a));
    }

    public boolean hasUnprocessedScopes() {
      return scopeStatus.entrySet().stream().anyMatch(this::entryIsUnprocessed);
    }

    public Set<String> getAllowedScopes() {
      return scopeStatus.entrySet()
        .stream()
        .filter(e -> ScopeStatus.PERMIT.equals(e.getValue()))
        .map(Map.Entry::getKey)
        .collect(Collectors.toSet());
    }

    public void forgetProcessedEntries() {
      Set<String> processedKeys = scopeStatus.entrySet()
        .stream()
        .filter(this::entryIsProcessed)
        .map(Map.Entry::getKey)
        .collect(Collectors.toSet());

      processedKeys.forEach(scopeStatus::remove);
    }

    @Override
    public String toString() {
      return "DecisionContext [" + scopeStatus + "]";
    }
  }

  private final IamScopePolicyRepository policyRepo;

  @Autowired
  public DefaultScopePolicyPDP(IamScopePolicyRepository policyRepo) {
    this.policyRepo = policyRepo;
  }

  protected Set<IamScopePolicy> resolveGroupScopePolicies(IamAccount account) {

    Set<IamScopePolicy> groupPolicies = Sets.newHashSet();

    Set<IamAccountGroupMembership> groups = account.getGroups();
    for (IamAccountGroupMembership g : groups) {
      groupPolicies.addAll(g.getGroup().getScopePolicies());
    }

    return groupPolicies;
  }

  @Override
  public Set<String> filterScopes(Set<String> requestedScopes, IamAccount account) {

    DecisionContext dc = new DecisionContext(matchersCache, requestedScopes);

    // Apply user policies
    for (IamScopePolicy p : account.getScopePolicies()) {
      dc.applyPolicy(p, account);
    }

    Set<String> allowedScopes = dc.getAllowedScopes();

    if (!dc.hasUnprocessedScopes()) {
      return allowedScopes;
    }

    Set<IamScopePolicy> groupPolicies = resolveGroupScopePolicies(account);

    // Apply group policies only on unprocessed scopes
    dc.forgetProcessedEntries();

    // Group policies are naturally composed with the deny overrides behaviour
    for (IamScopePolicy p : groupPolicies) {
      dc.applyPolicy(p, account);
    }

    allowedScopes.addAll(dc.getAllowedScopes());

    if (!dc.hasUnprocessedScopes()) {
      return allowedScopes;
    }

    dc.forgetProcessedEntries();

    List<IamScopePolicy> defaultPolicies = policyRepo.findDefaultPolicies();

    for (IamScopePolicy p : defaultPolicies) {
      dc.applyPolicy(p, account);
    }

    allowedScopes.addAll(dc.getAllowedScopes());
    return allowedScopes;
  }

}
