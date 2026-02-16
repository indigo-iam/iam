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
package it.infn.mw.iam.test.oauth.scope;

import static com.google.common.collect.Sets.newHashSet;
import static it.infn.mw.iam.core.oauth.scope.matchers.RegexpScopeMatcher.regexpMatcher;
import static it.infn.mw.iam.core.oauth.scope.matchers.StringEqualsScopeMatcher.stringEqualsMatcher;
import static it.infn.mw.iam.core.oauth.scope.matchers.StructuredPathScopeMatcher.structuredPathMatcher;
import static java.util.Collections.emptySet;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.mockito.Mockito.when;

import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.provider.ClientDetails;

import com.google.common.collect.Lists;
import com.google.common.collect.Sets;

import it.infn.mw.iam.core.oauth.scope.matchers.DefaultScopeMatcherRegistry;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcher;
import it.infn.mw.iam.persistence.model.SystemScope;
import it.infn.mw.iam.persistence.repository.IamSystemScopeRepository;

@SuppressWarnings("deprecation")
@ExtendWith(MockitoExtension.class)
class ScopeRegistryTests {

  @Mock
  ClientDetails client;

  @Mock
  IamSystemScopeRepository scopeRepo;

  @BeforeEach
  void setup() {
    SystemScope testScope = new SystemScope("test:/whatever");
    when(scopeRepo.findAll()).thenReturn(Lists.newArrayList(testScope));
  }

  @Test
  void testEmptyScopes() {

    DefaultScopeMatcherRegistry matcherRegistry =
        new DefaultScopeMatcherRegistry(emptySet(), scopeRepo);

    when(client.getScope()).thenReturn(Sets.newHashSet("openid", "profile"));
    Set<ScopeMatcher> matchers = matcherRegistry.findMatchersForClient(client);

    assertThat(matchers, not(nullValue()));
    assertThat(matchers, hasSize(2));
    assertThat(matchers, hasItem(stringEqualsMatcher("openid")));
    assertThat(matchers, hasItem(stringEqualsMatcher("profile")));
  }

  @Test
  void testNonMatchingScope() {

    DefaultScopeMatcherRegistry matcherRegistry =
        new DefaultScopeMatcherRegistry(newHashSet(regexpMatcher("^test:/.*$")), scopeRepo);

    when(client.getScope()).thenReturn(Sets.newHashSet("openid", "profile"));
    Set<ScopeMatcher> matchers = matcherRegistry.findMatchersForClient(client);

    assertThat(matchers, not(nullValue()));
    assertThat(matchers, hasSize(2));
    assertThat(matchers, hasItem(stringEqualsMatcher("openid")));
    assertThat(matchers, hasItem(stringEqualsMatcher("profile")));
  }

  @Test
  void testMatchingScope() {

    DefaultScopeMatcherRegistry matcherRegistry = new DefaultScopeMatcherRegistry(
        newHashSet(regexpMatcher("^test:/.*$"), structuredPathMatcher("storage.create", "/")),
        scopeRepo);

    when(client.getScope()).thenReturn(
        Sets.newHashSet("openid", "profile", "test", "test:/whatever", "storage.create:/whatever"));
    Set<ScopeMatcher> matchers = matcherRegistry.findMatchersForClient(client);

    assertThat(matchers, not(nullValue()));
    assertThat(matchers, hasSize(5));
    assertThat(matchers, hasItem(stringEqualsMatcher("openid")));
    assertThat(matchers, hasItem(stringEqualsMatcher("profile")));
    assertThat(matchers, hasItem(stringEqualsMatcher("test")));
    assertThat(matchers, hasItem(regexpMatcher("^test:/.*$")));
    assertThat(matchers, hasItem(stringEqualsMatcher("storage.create:/whatever")));
  }

}
