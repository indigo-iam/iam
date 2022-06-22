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
package it.infn.mw.iam.test.oauth.exchange;

import static it.infn.mw.iam.persistence.model.PolicyRule.DENY;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

import com.google.common.collect.Lists;

import it.infn.mw.iam.core.oauth.exchange.AnyClientMatcher;
import it.infn.mw.iam.core.oauth.exchange.ScopeExchangePolicy;
import it.infn.mw.iam.core.oauth.exchange.TokenExchangePolicy;
import it.infn.mw.iam.persistence.model.PolicyRule;



@RunWith(MockitoJUnitRunner.class)
public class TokenExchagePolicyBuilderTests extends TokenExchangePdpTestSupport{

  @Test
  public void builderTest() {
    TokenExchangePolicy policy = TokenExchangePolicy.builder()
      .withId(1L)
      .withDescription("Desc")
      .withOriginMatcher(new AnyClientMatcher())
      .withDestionationMatcher(new AnyClientMatcher())
      .withRule(PolicyRule.DENY)
      .withScopePolicies(null)
      .build();
    
    assertThat(policy.getId(), is(1L));
    assertThat(policy.getDescription(), is("Desc"));
    assertThat(policy.getOriginMatcher(), instanceOf(AnyClientMatcher.class));
    assertThat(policy.getDestinationMatcher(), instanceOf(AnyClientMatcher.class));
    assertThat(policy.getRule(), is(PolicyRule.DENY));
    assertThat(policy.scopePolicies(), notNullValue());
    
    
    List<ScopeExchangePolicy> sp = Lists.newArrayList();
    sp.add(ScopeExchangePolicy.fromEntity(buildScopePolicy(DENY, "s1")));
    
    policy = TokenExchangePolicy.builder()
        .withId(1L)
        .withDescription("Desc")
        .withOriginMatcher(new AnyClientMatcher())
        .withDestionationMatcher(new AnyClientMatcher())
        .withRule(PolicyRule.DENY)
        .withScopePolicies(sp)
        .build();
    
    assertThat(policy.getId(), is(1L));
    assertThat(policy.getDescription(), is("Desc"));
    assertThat(policy.getOriginMatcher(), instanceOf(AnyClientMatcher.class));
    assertThat(policy.getDestinationMatcher(), instanceOf(AnyClientMatcher.class));
    assertThat(policy.getRule(), is(PolicyRule.DENY));
    assertThat(policy.scopePolicies(), notNullValue());
    assertThat(policy.scopePolicies(), hasSize(1));
  }

}
