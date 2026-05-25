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
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mitre.oauth2.model.SystemScope;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.provider.ClientDetails;

import com.google.common.collect.Sets;

import it.infn.mw.iam.core.oauth.scope.matchers.DefaultScopeMatcherRegistry;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcher;
import it.infn.mw.iam.persistence.repository.IamScopeRepository;

@SuppressWarnings("deprecation")
@ExtendWith(MockitoExtension.class)
class ScopeRegistryTests {

  @Mock
  ClientDetails client;

  @Mock
  IamScopeRepository scopeRepo;

  @BeforeEach
  void setup() {

    SystemScope structuredTestScope = buildScope(1L, "test:/", false, false, true);
    SystemScope openidScope = buildScope(2L, "openid", true, false, false);
    SystemScope profileScope = buildScope(3L, "profile", false, false, false);
    SystemScope testScope = buildScope(4L, "test", false, false, false);
    lenient().when(scopeRepo.findAll())
      .thenReturn(List.of(structuredTestScope, openidScope, profileScope, testScope));
  }

  private SystemScope buildScope(Long id, String value, boolean isDefault, boolean isRestricted,
      boolean isStructured) {
    SystemScope scope = new SystemScope();
    scope.setId(id);
    scope.setValue(value);
    scope.setDefaultScope(isDefault);
    scope.setRestricted(isRestricted);
    scope.setStructured(isStructured);
    return scope;
  }

  @Test
  void testEmptyCustomScopeMatchers() {

    DefaultScopeMatcherRegistry matcherRegistry =
        new DefaultScopeMatcherRegistry(emptySet(), scopeRepo);

    when(client.getScope()).thenReturn(Sets.newHashSet("openid", "test", "test:/whatever"));
    Set<ScopeMatcher> matchers = matcherRegistry.findMatchersForClient(client);

    assertThat(matchers, not(nullValue()));
    assertThat(matchers, hasSize(3));
    assertThat(matchers, hasItem(stringEqualsMatcher("openid")));
    assertThat(matchers, hasItem(stringEqualsMatcher("test")));
    assertThat(matchers, hasItem(structuredPathMatcher("test", "/whatever")));
  }

  @Test
  void testRegexpMatchingStructuredScope() {

    DefaultScopeMatcherRegistry matcherRegistry =
        new DefaultScopeMatcherRegistry(newHashSet(regexpMatcher("^test:/.*$")), scopeRepo);

    when(client.getScope()).thenReturn(Sets.newHashSet("test"));
    Set<ScopeMatcher> matchers = matcherRegistry.findMatchersForClient(client);

    assertThat(matchers, not(nullValue()));
    assertThat(matchers, hasSize(1));
    assertThat(matchers, hasItem(stringEqualsMatcher("test")));

    when(client.getScope()).thenReturn(Sets.newHashSet("test:/path"));
    matchers = matcherRegistry.findMatchersForClient(client);

    assertThat(matchers, not(nullValue()));
    assertThat(matchers, hasSize(1));
    assertThat(matchers, hasItem(regexpMatcher("^test:/.*$")));
  }

  @Test
  void testMatchingScope() {

    DefaultScopeMatcherRegistry matcherRegistry =
        new DefaultScopeMatcherRegistry(emptySet(), scopeRepo);

    when(client.getScope()).thenReturn(
        Sets.newHashSet("openid", "profile", "test", "test:/whatever", "unknown-structured:/whatever", "unknown-scope"));
    Set<ScopeMatcher> matchers = matcherRegistry.findMatchersForClient(client);

    assertThat(matchers, not(nullValue()));
    assertThat(matchers, hasSize(6));
    assertThat(matchers, hasItem(stringEqualsMatcher("openid")));
    assertThat(matchers, hasItem(stringEqualsMatcher("profile")));
    assertThat(matchers, hasItem(stringEqualsMatcher("test")));
    assertThat(matchers, not(hasItem(regexpMatcher("^test:/.*$"))));
    assertThat(matchers, hasItem(structuredPathMatcher("test", "/whatever")));
    assertThat(matchers, hasItem(structuredPathMatcher("unknown-structured", "/whatever")));
    assertThat(matchers, hasItem(stringEqualsMatcher("unknown-scope")));
  }

}
