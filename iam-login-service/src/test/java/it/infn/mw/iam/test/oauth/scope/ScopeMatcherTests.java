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

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcher;
import it.infn.mw.iam.core.oauth.scope.matchers.StructuredPathScopeMatcher;


@RunWith(MockitoJUnitRunner.class)
public class ScopeMatcherTests {

  @Test
  public void testSimpleMatch() {

    ScopeMatcher matcher = structuredPathMatcher("read", "/");

    assertThat(matcher.matches("write"), is(false));
    assertThat(matcher.matches("read:/"), is(true));
    assertThat(matcher.matches("read:/pippo"), is(true));
    assertThat(matcher.matches("read:pippo"), is(false));
    assertThat(matcher.matches("read:/pippo/other#cheers"), is(true));

  }

  @Test
  public void testPathMatch() {

    ScopeMatcher matcher = structuredPathMatcher("read", "/path");

    assertThat(matcher.matches("read:/"), is(false));
    assertThat(matcher.matches("read:/other"), is(false));
    assertThat(matcher.matches("read:/path"), is(true));
    assertThat(matcher.matches("read:/path/path/path"), is(true));


  }

  @Test(expected = IllegalArgumentException.class)
  public void testScopeRelativePathDetection() {

    ScopeMatcher matcher = structuredPathMatcher("read", "/");

    final String[] TEST_CASES = {"read:/../example", "read:/ex/ample/.."};

    IllegalArgumentException lastExcept = null;

    for (String s : TEST_CASES) {
      try {
        matcher.matches(s);
      } catch (IllegalArgumentException e) {
        lastExcept = e;
        assertThat(e.getMessage(), containsString("relative path references"));
      }
    }
    if (lastExcept != null) {
      throw lastExcept;
    }
  }

  @Test(expected = IllegalArgumentException.class)
  public void noSeparatorInPrefix() {
    try {
      structuredPathMatcher("read:", "/");
    } catch (IllegalArgumentException e) {
      assertThat(e.getMessage(), containsString("prefix must not contain context separator"));
      throw e;
    }
  }

  @Test(expected = IllegalArgumentException.class)
  public void nullIsNotAllowed() {
    ScopeMatcher m = regexpMatcher("^wlcg(:1.0)?");
    m.matches(null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void nullIsNotAllowedStructured() {
    ScopeMatcher m = structuredPathMatcher("storage.read", "/");
    m.matches(null);
  }


  @Test
  public void testPathParsing() {

    StructuredPathScopeMatcher m = StructuredPathScopeMatcher.fromString("read:/");
    assertThat(m.getPrefix(), is("read"));
    assertThat(m.getPath(), is("/"));
  }

  @Test(expected = IllegalArgumentException.class)
  public void testNullPrefixException() {

    StructuredPathScopeMatcher.structuredPathMatcher(null, "/");

  }

  @Test(expected = IllegalArgumentException.class)
  public void emptyPrefixException() {

    StructuredPathScopeMatcher.structuredPathMatcher("", "/");

  }

  @Test(expected = IllegalArgumentException.class)
  public void testNullPathException() {

    StructuredPathScopeMatcher.structuredPathMatcher("test", null);

  }

  @Test(expected = IllegalArgumentException.class)
  public void emptyPathException() {

    StructuredPathScopeMatcher.structuredPathMatcher("test", "");
  }

  @Test
  public void testStructuredScopeEquals() {
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
  public void testStructuredScopeToString() {
    StructuredPathScopeMatcher m = StructuredPathScopeMatcher.structuredPathMatcher("test", "/");

    assertThat(m.toString(), is("test:/"));
  }

  @Test
  public void testStructuredScopeHashCode() {
    StructuredPathScopeMatcher m = StructuredPathScopeMatcher.structuredPathMatcher("test", "/");
    StructuredPathScopeMatcher m2 =
        StructuredPathScopeMatcher.structuredPathMatcher("test", "/path");
    StructuredPathScopeMatcher m3 =
        StructuredPathScopeMatcher.structuredPathMatcher("test", "/");

    assertThat(m.hashCode() == m2.hashCode(), is(false));
    assertThat(m.hashCode() == m3.hashCode(), is(true));

  }
}
