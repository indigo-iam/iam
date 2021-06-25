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

import static it.infn.mw.iam.core.oauth.exchange.TokenExchangePdpResult.Decision.NOT_APPLICABLE;
import static it.infn.mw.iam.core.oauth.granters.TokenExchangeTokenGranter.TOKEN_EXCHANGE_GRANT_TYPE;
import static it.infn.mw.iam.persistence.model.PolicyRule.DENY;
import static it.infn.mw.iam.persistence.model.PolicyRule.PERMIT;
import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Collections.emptyMap;
import static java.util.stream.Collectors.toSet;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.Collections;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.TokenRequest;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.TokenExchangeProperties;
import it.infn.mw.iam.core.oauth.exchange.DefaultTokenExchangePdp;
import it.infn.mw.iam.core.oauth.exchange.TokenExchangePdpResult;
import it.infn.mw.iam.core.oauth.exchange.TokenExchangePdpResult.Decision;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcherRegistry;
import it.infn.mw.iam.core.oauth.scope.matchers.StringEqualsScopeMatcher;
import it.infn.mw.iam.persistence.model.IamClientMatchingPolicy;
import it.infn.mw.iam.persistence.model.IamTokenExchangePolicyEntity;
import it.infn.mw.iam.persistence.repository.IamTokenExchangePolicyRepository;

@RunWith(MockitoJUnitRunner.class)
public class TokenExchangePdPTests extends TokenExchangePdpTestSupport {

  @Spy
  TokenRequest request = buildTokenRequest();

  @Mock
  ClientDetails originClient;

  @Mock
  ClientDetails destinationClient;

  @Mock
  IamTokenExchangePolicyRepository repo;

  @Mock
  IamProperties iamProperties;

  @Mock
  TokenExchangeProperties teProperties;

  @Mock
  ScopeMatcherRegistry scopeMatchersRegistry;

  DefaultTokenExchangePdp pdp;

  private TokenRequest buildTokenRequest() {
    return new TokenRequest(emptyMap(), "destination", Collections.emptySet(), TOKEN_EXCHANGE_GRANT_TYPE);
  }

  @Before
  public void before() {
    when(originClient.getClientId()).thenReturn(ORIGIN_CLIENT_ID);
    when(destinationClient.getClientId()).thenReturn(DESTINATION_CLIENT_ID);
    
    when(originClient.getScope()).thenReturn(ORIGIN_CLIENT_SCOPES);
    when(destinationClient.getScope()).thenReturn(DESTINATION_CLIENT_SCOPES);
    
    when(scopeMatchersRegistry.findMatchersForClient(originClient))
      .thenReturn(ORIGIN_CLIENT_SCOPES.stream()
        .map(StringEqualsScopeMatcher::stringEqualsMatcher)
        .collect(toSet()));
    when(repo.findAll()).thenReturn(emptyList());
    when(teProperties.getExpirePolicyCacheAfterSeconds()).thenReturn(60L);
    when(iamProperties.getTokenExchange()).thenReturn(teProperties);

    pdp = new DefaultTokenExchangePdp(iamProperties, repo, scopeMatchersRegistry);

  }

  @Test
  public void tokenExchangeDeniedByDefaultWhenNoPoliciesFound() {

    TokenExchangePdpResult result =
        pdp.validateTokenExchange(request, originClient, destinationClient);

    assertThat(result.decision(), is(NOT_APPLICABLE));
  }

  @Test
  public void tokenAllowAllExchanges() {

    IamTokenExchangePolicyEntity pe = buildPermitExamplePolicy(1L, "Allow all exchanges");

    when(repo.findAll()).thenReturn(Arrays.asList(pe));

    TokenExchangePdpResult result =
        pdp.validateTokenExchange(request, originClient, destinationClient);

    assertThat(result.decision(), is(Decision.PERMIT));
    assertThat(result.policy().isPresent(), is(true));
    assertThat(result.policy().get().getId(), is(1L));
    assertThat(result.policy().get().getDescription(), is("Allow all exchanges"));
  }

  @Test
  public void tokenDenyAllExchanges() {

    IamTokenExchangePolicyEntity pe = buildDenyExamplePolicy(1L, "Deny all exchanges");
    
    when(repo.findAll()).thenReturn(Arrays.asList(pe));

    TokenExchangePdpResult result =
        pdp.validateTokenExchange(request, originClient, destinationClient);
    assertThat(result.decision(), is(Decision.DENY));
    assertThat(result.policy().isPresent(), is(true));
    assertThat(result.policy().get().getId(), is(1L));
    assertThat(result.policy().get().getDescription(), is("Deny all exchanges"));

  }

  @Test
  public void testPolicyRankedCombination() {
    IamTokenExchangePolicyEntity p1 = buildDenyExamplePolicy(1L, "Deny all exchanges");
    
    IamTokenExchangePolicyEntity p2 = buildPermitExamplePolicy(2L, "Allow exchanges from client origin");
    p2.setOriginClient(buildByIdClientMatcher("origin"));
    
    when(repo.findAll()).thenReturn(Arrays.asList(p1, p2));

    TokenExchangePdpResult result =
        pdp.validateTokenExchange(request, originClient, destinationClient);

    assertThat(result.decision(), is(Decision.PERMIT));
    assertThat(result.policy().isPresent(), is(true));
    assertThat(result.policy().get().getId(), is(2L));
    assertThat(result.policy().get().getDescription(), is("Allow exchanges from client origin"));
  }

  @Test
  public void testSameRankDenyWins() {

    IamTokenExchangePolicyEntity p1 = buildPermitExamplePolicy(1L, "Allow all exchanges");
    IamTokenExchangePolicyEntity p2 = buildDenyExamplePolicy(2L, "Deny all exchanges");
    IamTokenExchangePolicyEntity p3 = buildPermitExamplePolicy(3L, "Allow all exchanges");
    
    when(repo.findAll()).thenReturn(asList(p1, p2, p3));

    TokenExchangePdpResult result =
        pdp.validateTokenExchange(request, originClient, destinationClient);

    assertThat(result.decision(), is(Decision.DENY));
    assertThat(result.policy().isPresent(), is(true));
    assertThat(result.policy().get().getId(), is(2L));
    assertThat(result.policy().get().getDescription(), is("Deny all exchanges"));

  }

  @Test
  public void rankingWorksAsExpected() {

    IamTokenExchangePolicyEntity p1 = buildPermitExamplePolicy(1L, "Allow exchanges between scope s2 clients");
    
    IamClientMatchingPolicy s2ScopeClient =  buildByScopeClientMatcher("s2");
    p1.setOriginClient(s2ScopeClient);
    p1.setDestinationClient(s2ScopeClient);
    
    IamTokenExchangePolicyEntity p2 = buildDenyExamplePolicy(2L,"Deny exchanges between origin and scope s2 clients");
    p2.setOriginClient(buildByIdClientMatcher("origin"));
    p2.setDestinationClient(s2ScopeClient);
    
    when(repo.findAll()).thenReturn(asList(p1, p2));

    TokenExchangePdpResult result =
        pdp.validateTokenExchange(request, originClient, destinationClient);

    assertThat(result.decision(), is(Decision.DENY));
    assertThat(result.policy().isPresent(), is(true));
    assertThat(result.policy().get().getId(), is(2L));
    assertThat(result.policy().get().getDescription(),
        is("Deny exchanges between origin and scope s2 clients"));
  }

  @Test
  public void clientScopeCheckingWorks() {
    IamTokenExchangePolicyEntity p1 = buildPermitExamplePolicy(1L, "Allow all exchanges");
    request.setScope(asList("s5"));
    
    when(repo.findAll()).thenReturn(asList(p1));
    
    TokenExchangePdpResult result =
        pdp.validateTokenExchange(request, originClient, destinationClient);
    
    assertThat(result.decision(), is(Decision.INVALID_SCOPE));
    assertThat(result.message().isPresent(), is(true));
    assertThat(result.message().get(), is("scope not allowed by client configuration"));
  }
  
  @Test
  public void clientScopeCheckWorks() {
    IamTokenExchangePolicyEntity p1 = buildPermitExamplePolicy(1L, "Allow all exchanges");
    request.setScope(asList("s1","s2"));
    
    when(repo.findAll()).thenReturn(asList(p1));
    
    TokenExchangePdpResult result =
        pdp.validateTokenExchange(request, originClient, destinationClient);
    
    assertThat(result.decision(), is(Decision.PERMIT)); 
  }
  
  @Test
  public void scopeExchangeDenyPolicyWorks() {
    IamTokenExchangePolicyEntity p1 = buildPermitExamplePolicy(1L, "Allow all exchanges");
    request.setScope(asList("s2", "s1"));
    
    p1.getScopePolicies().add(buildScopePolicy(DENY, "s1"));
    p1.getScopePolicies().add(buildScopePolicy(PERMIT, "s2"));
    
    when(repo.findAll()).thenReturn(asList(p1));
    
    TokenExchangePdpResult result =
        pdp.validateTokenExchange(request, originClient, destinationClient);
    
    assertThat(result.decision(), is(Decision.INVALID_SCOPE));
    
    assertThat(result.invalidScope().isPresent(), is (true));
    assertThat(result.invalidScope().get(), is("s1"));
    assertThat(result.message().isPresent(), is (true));
    assertThat(result.message().get(), is("scope exchange not allowed by policy"));
  }
}
