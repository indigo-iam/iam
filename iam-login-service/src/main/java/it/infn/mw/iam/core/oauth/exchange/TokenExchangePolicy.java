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

import static it.infn.mw.iam.core.oauth.exchange.ClientMatcherFactory.newClientMatcher;

import java.util.List;
import java.util.Objects;

import org.springframework.security.oauth2.provider.ClientDetails;

import com.google.common.collect.Lists;

import it.infn.mw.iam.persistence.model.IamTokenExchangePolicyEntity;
import it.infn.mw.iam.persistence.model.IamTokenExchangeScopePolicy;
import it.infn.mw.iam.persistence.model.PolicyRule;

@SuppressWarnings("deprecation")
public class TokenExchangePolicy {
  private final Long id;

  private final String description;

  private final PolicyRule rule;

  private final ClientMatcher originMatcher;

  private final ClientMatcher destinationMatcher;

  private final List<ScopeExchangePolicy> scopePolicies;

  private TokenExchangePolicy(Builder b) {
    id = b.id;
    description = b.description;
    rule = b.rule;
    originMatcher = b.originMatcher;
    destinationMatcher = b.destinationMatcher;
    scopePolicies = b.scopePolicies;
  }

  public boolean appicableFor(ClientDetails originClient, ClientDetails destinationClient) {
    return originMatcher.matchesClient(originClient)
        && destinationMatcher.matchesClient(destinationClient);
  }

  public int rank() {
    return originMatcher.rank() + destinationMatcher.rank();
  }

  public static Builder builder() {
    return new Builder();
  }

  public List<ScopeExchangePolicy> scopePolicies() {
    return scopePolicies;
  }

  public static class Builder {
    Long id = null;
    String description = null;
    PolicyRule rule = PolicyRule.DENY;
    ClientMatcher originMatcher = new AnyClientMatcher();
    ClientMatcher destinationMatcher = new AnyClientMatcher();
    List<ScopeExchangePolicy> scopePolicies = Lists.newArrayList();

    public Builder withId(Long id) {
      this.id = id;
      return this;
    }

    public Builder withDescription(String description) {
      this.description = description;
      return this;
    }

    public Builder withRule(PolicyRule rule) {
      this.rule = rule;
      return this;
    }

    public Builder withOriginMatcher(ClientMatcher matcher) {
      this.originMatcher = matcher;
      return this;
    }

    public Builder withDestionationMatcher(ClientMatcher matcher) {
      this.destinationMatcher = matcher;
      return this;
    }
    
    public Builder withScopePolicies(List<ScopeExchangePolicy> scopePolicies) {
      if (!Objects.isNull(scopePolicies)) {
        this.scopePolicies = scopePolicies;
      }
      
      return this;
    }

    public TokenExchangePolicy build() {
      return new TokenExchangePolicy(this);
    }

    public Builder fromEntity(IamTokenExchangePolicyEntity e) {
      this.id = e.getId();
      this.description = e.getDescription();
      this.rule = e.getRule();
      this.originMatcher = newClientMatcher(e.getOriginClient());
      this.destinationMatcher = newClientMatcher(e.getDestinationClient());

      for (IamTokenExchangeScopePolicy sp : e.getScopePolicies()) {
        scopePolicies.add(ScopeExchangePolicy.fromEntity(sp));
      }

      return this;
    }
  }

  public Long getId() {
    return id;
  }

  public String getDescription() {
    return description;
  }

  public PolicyRule getRule() {
    return rule;
  }

  public boolean isDeny() {
    return PolicyRule.DENY.equals(rule);
  }
  
  public ClientMatcher getOriginMatcher() {
    return originMatcher;
  }
  
  public ClientMatcher getDestinationMatcher() {
    return destinationMatcher;
  }
}
