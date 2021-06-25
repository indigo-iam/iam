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
package it.infn.mw.iam.test.oauth.exchange;

import static it.infn.mw.iam.persistence.model.IamScopePolicy.MatchingPolicy.EQ;

import java.util.Set;

import org.mockito.Mockito;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import com.google.common.collect.Sets;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.exchange.DefaultTokenExchangePdp;
import it.infn.mw.iam.core.oauth.exchange.TokenExchangePdp;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcherRegistry;
import it.infn.mw.iam.persistence.model.IamClientMatchingPolicy;
import it.infn.mw.iam.persistence.model.IamClientMatchingPolicy.ClientMatchingPolicyType;
import it.infn.mw.iam.persistence.model.IamTokenExchangePolicyEntity;
import it.infn.mw.iam.persistence.model.IamTokenExchangeScopePolicy;
import it.infn.mw.iam.persistence.model.PolicyRule;
import it.infn.mw.iam.persistence.repository.IamTokenExchangePolicyRepository;

@Configuration
public class TokenExchangePdpTestSupport {

  public static final String ORIGIN_CLIENT_ID = "origin";
  public static final String DESTINATION_CLIENT_ID = "destination";

  public static final Set<String> ORIGIN_CLIENT_SCOPES = Sets.newHashSet("s1", "s2");
  public static final Set<String> DESTINATION_CLIENT_SCOPES = Sets.newHashSet("s2", "s3");

  public IamTokenExchangePolicyEntity buildExamplePolicy(Long id, PolicyRule rule,
      String description) {
    IamClientMatchingPolicy anyClient = new IamClientMatchingPolicy();
    anyClient.setType(ClientMatchingPolicyType.ANY);

    IamTokenExchangePolicyEntity pe = new IamTokenExchangePolicyEntity();
    pe.setId(id);
    pe.setDescription(description);
    pe.setRule(rule);
    pe.setOriginClient(anyClient);
    pe.setDestinationClient(anyClient);
    return pe;
  }

  public IamTokenExchangePolicyEntity buildPermitExamplePolicy(Long id, String description) {
    return buildExamplePolicy(id, PolicyRule.PERMIT, description);
  }


  public IamTokenExchangePolicyEntity buildDenyExamplePolicy(Long id, String description) {
    return buildExamplePolicy(id, PolicyRule.DENY, description);
  }


  public IamClientMatchingPolicy buildAnyClientMatcher() {
    IamClientMatchingPolicy anyClient = new IamClientMatchingPolicy();
    anyClient.setType(ClientMatchingPolicyType.ANY);
    return anyClient;
  }

  public IamClientMatchingPolicy buildByIdClientMatcher(String clientId) {
    IamClientMatchingPolicy client = new IamClientMatchingPolicy();
    client.setType(ClientMatchingPolicyType.BY_ID);
    client.setMatchParam(clientId);
    return client;
  }

  public IamClientMatchingPolicy buildByScopeClientMatcher(String scope) {
    IamClientMatchingPolicy client = new IamClientMatchingPolicy();
    client.setType(ClientMatchingPolicyType.BY_SCOPE);
    client.setMatchParam(scope);
    return client;
  }

  public IamTokenExchangeScopePolicy buildPermitScopePolicy(String scope) {
    return buildScopePolicy(PolicyRule.PERMIT, scope);
  }

  public IamTokenExchangeScopePolicy buildScopePolicy(PolicyRule rule, String scope) {
    IamTokenExchangeScopePolicy policy = new IamTokenExchangeScopePolicy();
    policy.setRule(rule);
    policy.setType(EQ);
    policy.setMatchParam(scope);

    return policy;
  }

  @Bean
  @Primary
  TokenExchangePdp tokenExchangePdp(IamProperties properties, IamTokenExchangePolicyRepository repo,
      ScopeMatcherRegistry registry) {
    DefaultTokenExchangePdp pdp = new DefaultTokenExchangePdp(properties, repo, registry);

    return Mockito.spy(pdp);
  }

}
