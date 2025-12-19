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

import static it.infn.mw.iam.core.oauth.scope.matchers.RegexpScopeMatcher.regexpMatcher;
import static it.infn.mw.iam.core.oauth.scope.matchers.StructuredPathScopeMatcher.structuredPathMatcher;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcher;
import it.infn.mw.iam.core.oauth.scope.matchers.StructuredPathScopeMatcher;

@ExtendWith(MockitoExtension.class)
class ScopeMatcherTests {

  @Test
  void testSimpleMatch() {

    ScopeMatcher matcher = structuredPathMatcher("read", "/");

    assertThat(matcher.matches("write"), is(false));
    assertThat(matcher.matches("read:/"), is(true));
    assertThat(matcher.matches("read:/pippo"), is(true));
    assertThat(matcher.matches("read:pippo"), is(false));
    assertThat(matcher.matches("read:/pippo/other#cheers"), is(true));
  }

  @Test
  void testPathMatch() {

    ScopeMatcher matcher = structuredPathMatcher("read", "/path");

    assertThat(matcher.matches("read:/"), is(false));
    assertThat(matcher.matches("read:/other"), is(false));
    assertThat(matcher.matches("read:/path"), is(true));
    assertThat(matcher.matches("read:/path/path/path"), is(true));
  }

  @Test
  void testScopeRelativePathDetection() {

    ScopeMatcher matcher = structuredPathMatcher("read", "/");

    final String[] TEST_CASES = {"read:/../example", "read:/ex/ample/.."};

    for (String s : TEST_CASES) {
      IllegalArgumentException e =
          assertThrows(IllegalArgumentException.class, () -> matcher.matches(s));
      assertThat(e.getMessage(), containsString("relative path references"));
    }
  }

  @Test
  void noSeparatorInPrefix() {

    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> structuredPathMatcher("read:", "/"));
    assertThat(e.getMessage(), containsString("prefix must not contain context separator"));
  }

  @Test
  void nullIsNotAllowed() {

    ScopeMatcher m = regexpMatcher("^wlcg(:1.0)?");
    assertThrows(IllegalArgumentException.class, () -> m.matches(null));
  }

  @Test
  void nullIsNotAllowedStructured() {

    ScopeMatcher m = structuredPathMatcher("storage.read", "/");
    assertThrows(IllegalArgumentException.class, () -> m.matches(null));
  }

  @Test
  void testPathParsing() {

    StructuredPathScopeMatcher m = StructuredPathScopeMatcher.fromString("read:/");
    assertThat(m.getPrefix(), is("read"));
    assertThat(m.getPath(), is("/"));
  }

  @Test
  void testNullPrefixException() {

    assertThrows(IllegalArgumentException.class,
        () -> StructuredPathScopeMatcher.structuredPathMatcher(null, "/"));
  }

  @Test
  void emptyPrefixException() {

    assertThrows(IllegalArgumentException.class,
        () -> StructuredPathScopeMatcher.structuredPathMatcher("", "/"));
  }

  @Test
  void testNullPathException() {

    assertThrows(IllegalArgumentException.class,
        () -> StructuredPathScopeMatcher.structuredPathMatcher("test", null));
  }

  @Test
  void emptyPathException() {

    assertThrows(IllegalArgumentException.class,
        () -> StructuredPathScopeMatcher.structuredPathMatcher("test", ""));
  }

  @Test
  void testStructuredScopeEquals() {

    StructuredPathScopeMatcher m = StructuredPathScopeMatcher.structuredPathMatcher("test", "/");
    StructuredPathScopeMatcher m2 = StructuredPathScopeMatcher.structuredPathMatcher("test", "/");
    StructuredPathScopeMatcher m3 = StructuredPathScopeMatcher.structuredPathMatcher("other", "/");
    StructuredPathScopeMatcher m4 =
        StructuredPathScopeMatcher.structuredPathMatcher("test", "/other");

    assertThat(m, is(m));
    assertThat(m.equals(null), is(false));
    assertThat(m, is(m2));
    assertThat(m, is(not(m3)));
    assertThat(m, is(not(m4)));
  }

  @Test
  void testStructuredScopeToString() {

    StructuredPathScopeMatcher m = StructuredPathScopeMatcher.structuredPathMatcher("test", "/");
    assertThat(m.toString(), is("test:/"));
  }

  @Test
  void testStructuredScopeHashCode() {

    StructuredPathScopeMatcher m = StructuredPathScopeMatcher.structuredPathMatcher("test", "/");
    StructuredPathScopeMatcher m2 =
        StructuredPathScopeMatcher.structuredPathMatcher("test", "/path");
    StructuredPathScopeMatcher m3 =
        StructuredPathScopeMatcher.structuredPathMatcher("test", "/");

    assertThat(m.hashCode() == m2.hashCode(), is(false));
    assertThat(m.hashCode() == m3.hashCode(), is(true));
  }
}
