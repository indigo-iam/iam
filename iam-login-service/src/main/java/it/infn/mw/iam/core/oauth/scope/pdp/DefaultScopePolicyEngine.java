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

import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.collect.Sets;

import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcher;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAccountGroupMembership;
import it.infn.mw.iam.persistence.model.IamScopePolicy;
import it.infn.mw.iam.persistence.repository.IamScopePolicyRepository;

@Component
@ConditionalOnProperty(name = "iam.opa.enable", havingValue = "false")
public class DefaultScopePolicyEngine implements ScopePolicyEngine {
  public static final Logger LOG = LoggerFactory.getLogger(DefaultScopePolicyEngine.class);
  private Cache<String, ScopeMatcher> matchersCache = CacheBuilder.newBuilder().maximumSize(30).build();
  private final IamScopePolicyRepository policyRepo;

  public DefaultScopePolicyEngine(IamScopePolicyRepository policyRepo) {
    this.policyRepo = policyRepo;
  }

  @Override
  public Set<String> apply(Set<String> requestedScopes, IamAccount account) {
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

    // Group policies are naturally composed with the deny overrides behavior
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

  private Set<IamScopePolicy> resolveGroupScopePolicies(IamAccount account) {
    Set<IamScopePolicy> groupPolicies = Sets.newHashSet();

    Set<IamAccountGroupMembership> groups = account.getGroups();
    for (IamAccountGroupMembership g : groups) {
      groupPolicies.addAll(g.getGroup().getScopePolicies());
    }

    return groupPolicies;
  }
}
