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

import static it.infn.mw.iam.core.oauth.exchange.TokenExchangePdpResult.Decision.NOT_APPLICABLE;
import static it.infn.mw.iam.core.oauth.granters.TokenExchangeTokenGranter.TOKEN_EXCHANGE_GRANT_TYPE;
import static it.infn.mw.iam.persistence.model.PolicyRule.DENY;
import static it.infn.mw.iam.persistence.model.PolicyRule.PERMIT;
import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Collections.emptyMap;
import static java.util.stream.Collectors.toSet;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.lenient;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import org.apache.velocity.exception.ParseErrorException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.TokenRequest;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import it.infn.mw.iam.core.IamTokenService;
import it.infn.mw.iam.core.oauth.exchange.DefaultTokenExchangePdp;
import it.infn.mw.iam.core.oauth.exchange.TokenExchangePdpResult;
import it.infn.mw.iam.core.oauth.exchange.TokenExchangePdpResult.Decision;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcher;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcherRegistry;
import it.infn.mw.iam.core.oauth.scope.matchers.StringEqualsScopeMatcher;
import it.infn.mw.iam.persistence.model.IamClientMatchingPolicy;
import it.infn.mw.iam.persistence.model.IamTokenExchangePolicyEntity;
import it.infn.mw.iam.persistence.repository.IamTokenExchangePolicyRepository;


@SuppressWarnings("deprecation")
@ExtendWith(MockitoExtension.class)
class TokenExchangePdPTests extends TokenExchangePdpTestSupport {

  @Spy
  TokenRequest request = buildTokenRequest();

  @Mock
  ClientDetailsEntity originClient;

  @Mock
  ClientDetailsEntity destinationClient;

  @Mock
  IamTokenExchangePolicyRepository repo;

  @Mock
  ScopeMatcherRegistry scopeMatchersRegistry;

  DefaultTokenExchangePdp pdp;

  @Mock
  IamTokenService tokenService;

  private ListAppender<ILoggingEvent> logCaptor;

  // These are not tests of the Upscoping, thus the scopes extracted from the token is not what is
  // in question. Therefore, it should always make the static scopematchers for the token.
  class TestableDefaultTokenExchangePdp extends DefaultTokenExchangePdp {

    private final Set<ScopeMatcher> scopesToReturn;

    TestableDefaultTokenExchangePdp(IamTokenExchangePolicyRepository repo,
        ScopeMatcherRegistry scopeMatcherRegistry, IamTokenService tokenService,
        Set<ScopeMatcher> scopesToReturn) {

      super(repo, scopeMatcherRegistry, tokenService);
      this.scopesToReturn = scopesToReturn;
    }

    @Override
    protected Set<ScopeMatcher> extractScopesFromToken(String subjectToken) {
      return scopesToReturn;
    }
  }

  static final Set<ScopeMatcher> FIXED_MATCHERS =
      Set.of(StringEqualsScopeMatcher.stringEqualsMatcher("s1"),
          StringEqualsScopeMatcher.stringEqualsMatcher("s2"));

  private ListAppender<ILoggingEvent> attachLogCaptor(Class<?> clazz) {
    Logger logger = (Logger) org.slf4j.LoggerFactory.getLogger(clazz);
    ListAppender<ILoggingEvent> listAppender = new ListAppender<>();
    listAppender.start();
    logger.addAppender(listAppender);
    return listAppender;
  }

  private TokenRequest buildTokenRequest() {
    return new TokenRequest(emptyMap(), "destination", Collections.emptySet(),
        TOKEN_EXCHANGE_GRANT_TYPE);
  }


  @BeforeEach
  void before() {

    pdp = new TestableDefaultTokenExchangePdp(repo, scopeMatchersRegistry, tokenService,
        FIXED_MATCHERS);

    lenient().when(originClient.getClientId()).thenReturn(ORIGIN_CLIENT_ID);
    lenient().when(originClient.getScope()).thenReturn(ORIGIN_CLIENT_SCOPES);
    lenient().when(destinationClient.getScope()).thenReturn(DESTINATION_CLIENT_SCOPES);
    lenient().when(scopeMatchersRegistry.findMatchersForClient(originClient))
      .thenReturn(ORIGIN_CLIENT_SCOPES.stream()
        .map(StringEqualsScopeMatcher::stringEqualsMatcher)
        .collect(toSet()));
    lenient().when(repo.findAll()).thenReturn(emptyList());
    pdp.reloadPolicies();
    lenient().when(request.getRequestParameters()).thenReturn(Map.of("subject_token", "Not empty"));
  }

  @Test
  void tokenExchangeDeniedByDefaultWhenNoPoliciesFound() {

    TokenExchangePdpResult result =
        pdp.validateTokenExchange(request, originClient, destinationClient);

    assertThat(result.decision(), is(NOT_APPLICABLE));
  }

  @Test
  void tokenAllowAllExchanges() {

    IamTokenExchangePolicyEntity pe = buildPermitExamplePolicy(1L, "Allow all exchanges");

    lenient().when(repo.findAll()).thenReturn(Arrays.asList(pe));
    pdp.reloadPolicies();

    TokenExchangePdpResult result =
        pdp.validateTokenExchange(request, originClient, destinationClient);

    assertThat(result.decision(), is(Decision.PERMIT));
    assertThat(result.policy().isPresent(), is(true));
    assertThat(result.policy().get().getId(), is(1L));
    assertThat(result.policy().get().getDescription(), is("Allow all exchanges"));
  }

  @Test
  void tokenDenyAllExchanges() {

    IamTokenExchangePolicyEntity pe = buildDenyExamplePolicy(1L, "Deny all exchanges");

    lenient().when(repo.findAll()).thenReturn(Arrays.asList(pe));
    pdp.reloadPolicies();

    TokenExchangePdpResult result =
        pdp.validateTokenExchange(request, originClient, destinationClient);
    assertThat(result.decision(), is(Decision.DENY));
    assertThat(result.policy().isPresent(), is(true));
    assertThat(result.policy().get().getId(), is(1L));
    assertThat(result.policy().get().getDescription(), is("Deny all exchanges"));

  }

  @Test
  void testPolicyRankedCombination() {
    IamTokenExchangePolicyEntity p1 = buildDenyExamplePolicy(1L, "Deny all exchanges");

    IamTokenExchangePolicyEntity p2 =
        buildPermitExamplePolicy(2L, "Allow exchanges from client origin");
    p2.setOriginClient(buildByIdClientMatcher("origin"));

    lenient().when(repo.findAll()).thenReturn(Arrays.asList(p1, p2));
    pdp.reloadPolicies();

    TokenExchangePdpResult result =
        pdp.validateTokenExchange(request, originClient, destinationClient);

    assertThat(result.decision(), is(Decision.PERMIT));
    assertThat(result.policy().isPresent(), is(true));
    assertThat(result.policy().get().getId(), is(2L));
    assertThat(result.policy().get().getDescription(), is("Allow exchanges from client origin"));
  }

  @Test
  void testSameRankDenyWins() {

    IamTokenExchangePolicyEntity p1 = buildPermitExamplePolicy(1L, "Allow all exchanges");
    IamTokenExchangePolicyEntity p2 = buildDenyExamplePolicy(2L, "Deny all exchanges");
    IamTokenExchangePolicyEntity p3 = buildPermitExamplePolicy(3L, "Allow all exchanges");

    lenient().when(repo.findAll()).thenReturn(asList(p1, p2, p3));
    pdp.reloadPolicies();

    TokenExchangePdpResult result =
        pdp.validateTokenExchange(request, originClient, destinationClient);

    assertThat(result.decision(), is(Decision.DENY));
    assertThat(result.policy().isPresent(), is(true));
    assertThat(result.policy().get().getId(), is(2L));
    assertThat(result.policy().get().getDescription(), is("Deny all exchanges"));

  }

  @Test
  void rankingWorksAsExpected() {

    IamTokenExchangePolicyEntity p1 =
        buildPermitExamplePolicy(1L, "Allow exchanges between scope s2 clients");

    IamClientMatchingPolicy s2ScopeClient = buildByScopeClientMatcher("s2");
    p1.setOriginClient(s2ScopeClient);
    p1.setDestinationClient(s2ScopeClient);

    IamTokenExchangePolicyEntity p2 =
        buildDenyExamplePolicy(2L, "Deny exchanges between origin and scope s2 clients");
    p2.setOriginClient(buildByIdClientMatcher("origin"));
    p2.setDestinationClient(s2ScopeClient);

    lenient().when(repo.findAll()).thenReturn(asList(p1, p2));
    pdp.reloadPolicies();

    TokenExchangePdpResult result =
        pdp.validateTokenExchange(request, originClient, destinationClient);

    assertThat(result.decision(), is(Decision.DENY));
    assertThat(result.policy().isPresent(), is(true));
    assertThat(result.policy().get().getId(), is(2L));
    assertThat(result.policy().get().getDescription(),
        is("Deny exchanges between origin and scope s2 clients"));
  }

  @Test
  void clientScopeCheckingWorks() {
    IamTokenExchangePolicyEntity p1 = buildPermitExamplePolicy(1L, "Allow all exchanges");
    request.setScope(asList("s5"));

    lenient().when(repo.findAll()).thenReturn(asList(p1));
    pdp.reloadPolicies();

    TokenExchangePdpResult result =
        pdp.validateTokenExchange(request, originClient, destinationClient);

    assertThat(result.decision(), is(Decision.INVALID_SCOPE));
    assertThat(result.message().isPresent(), is(true));
    assertThat(result.message().get(), is("scope not allowed by origin client configuration"));
  }

  @Test
  void clientOriginScopeCheckingWorks() {
    IamTokenExchangePolicyEntity p1 = buildPermitExamplePolicy(1L, "Allow all exchanges");
    request.setScope(asList("s3"));

    lenient().when(repo.findAll()).thenReturn(asList(p1));
    pdp.reloadPolicies();

    TokenExchangePdpResult result =
        pdp.validateTokenExchange(request, originClient, destinationClient);

    assertThat(result.decision(), is(Decision.INVALID_SCOPE));
    assertThat(result.message().isPresent(), is(true));
    assertThat(result.message().get(), is("scope not allowed by origin client configuration"));
  }

  @Test
  void clientScopeCheckWorks() {
    IamTokenExchangePolicyEntity p1 = buildPermitExamplePolicy(1L, "Allow all exchanges");
    request.setScope(asList("s1", "s2"));

    lenient().when(repo.findAll()).thenReturn(asList(p1));
    pdp.reloadPolicies();

    TokenExchangePdpResult result =
        pdp.validateTokenExchange(request, originClient, destinationClient);

    assertThat(result.decision(), is(Decision.PERMIT));
  }

  @Test
  void scopeExchangeDenyPolicyWorks() {
    IamTokenExchangePolicyEntity p1 = buildPermitExamplePolicy(1L, "Allow all exchanges");
    request.setScope(asList("s2", "s1"));

    p1.getScopePolicies().add(buildScopePolicy(DENY, "s1"));
    p1.getScopePolicies().add(buildScopePolicy(PERMIT, "s2"));

    lenient().when(repo.findAll()).thenReturn(asList(p1));
    pdp.reloadPolicies();

    TokenExchangePdpResult result =
        pdp.validateTokenExchange(request, originClient, destinationClient);

    assertThat(result.decision(), is(Decision.INVALID_SCOPE));

    assertThat(result.invalidScope().isPresent(), is(true));
    assertThat(result.invalidScope().get(), is("s1"));
    assertThat(result.message().isPresent(), is(true));
    assertThat(result.message().get(), is("scope exchange not allowed by policy"));
  }

  @Test
  void scopeExchangeDenyPolicyWithRegexpWorks() {
    IamTokenExchangePolicyEntity p1 = buildPermitExamplePolicy(1L, "Allow all exchanges");
    request.setScope(asList("s2", "s1"));

    p1.getScopePolicies().add(buildScopePolicy(DENY, "s1"));
    p1.getScopePolicies().add(buildRegexpAllScopePolicy(PERMIT));

    lenient().when(repo.findAll()).thenReturn(asList(p1));
    pdp.reloadPolicies();

    TokenExchangePdpResult result =
        pdp.validateTokenExchange(request, originClient, destinationClient);

    assertThat(result.decision(), is(Decision.INVALID_SCOPE));

    assertThat(result.invalidScope().isPresent(), is(true));
    assertThat(result.invalidScope().get(), is("s1"));
    assertThat(result.message().isPresent(), is(true));
    assertThat(result.message().get(), is("scope exchange not allowed by policy"));
  }

  @Test
  void scopeExchangeDenyAllScopesPolicyWorks() {
    IamTokenExchangePolicyEntity p1 = buildPermitExamplePolicy(1L, "Allow all exchanges");
    request.setScope(asList("s2", "s1"));

    // A permit policy that denies all scopes that does not make much sense in practice,
    // but we want to verify it works
    p1.getScopePolicies().add(buildRegexpAllScopePolicy(DENY));

    lenient().when(repo.findAll()).thenReturn(asList(p1));
    pdp.reloadPolicies();

    TokenExchangePdpResult result =
        pdp.validateTokenExchange(request, originClient, destinationClient);

    assertThat(result.decision(), is(Decision.INVALID_SCOPE));

    assertThat(result.invalidScope().isPresent(), is(true));
    assertThat(result.invalidScope().get(), is("s2"));
    assertThat(result.message().isPresent(), is(true));
    assertThat(result.message().get(), is("scope exchange not allowed by policy"));
  }

  @Test
  void tokenExchangeWrongClientType() {

    ClientDetails destinationClientWrongType = Mockito.mock(ClientDetails.class);

    IamTokenExchangePolicyEntity p1 = buildPermitExamplePolicy(1L, "Allow all exchanges");
    request.setScope(asList("s1", "s2"));

    lenient().when(repo.findAll()).thenReturn(asList(p1));
    pdp.reloadPolicies();

    TokenExchangePdpResult result =
        pdp.validateTokenExchange(request, originClient, destinationClientWrongType);

    assertThat(result.decision(), is(Decision.DENY));
    assertThat(result.message().get(),
        is("Destination client type not supported for token exchange"));
  }

  @Test
  void tokenExchangeWrongNoSubjectToken() {

    IamTokenExchangePolicyEntity p1 = buildPermitExamplePolicy(1L, "Allow all exchanges");
    request.setScope(asList("s1", "s2"));

    lenient().when(repo.findAll()).thenReturn(asList(p1));
    pdp.reloadPolicies();

    lenient().when(request.getRequestParameters()).thenReturn(Map.of("subject_token", ""));

    TokenExchangePdpResult result =
        pdp.validateTokenExchange(request, originClient, destinationClient);

    assertThat(result.decision(), is(Decision.DENY));
    assertThat(result.message().get(), is("Subject token not present in request"));
  }


  // This test is more for completion, an invalid subject token shouldn't be possible at this point.
  @Test
  void extractScopesFromTokenInvalidFail() throws Exception {

    pdp = new DefaultTokenExchangePdp(repo, scopeMatchersRegistry, tokenService);

    // Method is not meant to be visible passed the package, so will have to change visibility
    Method method =
        DefaultTokenExchangePdp.class.getDeclaredMethod("extractScopesFromToken", String.class);
    method.setAccessible(true);
    String invalidJwt = "this-is-not-a-jwt";
    Mockito.when(tokenService.readAccessToken(invalidJwt))
      .thenThrow(new InvalidTokenException("Access Token not found"));
    logCaptor = attachLogCaptor(DefaultTokenExchangePdp.class);

    // Parse Error expected after both attempts fail
    try {
      method.invoke(pdp, invalidJwt);
      fail("Expected ParseErrorException to be thrown");
    } catch (InvocationTargetException e) {

      // Needing to unwrap the error
      Throwable cause = e.getCause();

      assertThat(cause, instanceOf(ParseErrorException.class));
      assertThat(cause.getMessage(),
          is("Error whilst extracting scopes from the token and failed token introspection"));
    }
    // Catching that it also fails the first introspection due to an error
    boolean found = logCaptor.list.stream()
      .anyMatch(event -> event.getLevel() == Level.WARN
          && event.getFormattedMessage()
            .contains("JWT parsing failed, attempting token introspection")
          && event.getThrowableProxy().getClassName().equals("java.text.ParseException"));

    assertTrue(found);
  }
}
