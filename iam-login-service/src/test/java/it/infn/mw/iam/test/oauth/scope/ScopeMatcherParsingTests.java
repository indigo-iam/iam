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
import static java.util.Arrays.asList;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.Set;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcher;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatchersProperties;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatchersProperties.MatcherProperties;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatchersProperties.MatcherProperties.MatcherType;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatchersPropertiesParser;

@RunWith(MockitoJUnitRunner.class)
public class ScopeMatcherParsingTests {

  ScopeMatchersProperties p = new ScopeMatchersProperties();
  
  @Test
  public void testEmptyParsing() {
    
    ScopeMatchersPropertiesParser parser = new ScopeMatchersPropertiesParser();
    Set<ScopeMatcher> matchers = parser.parseScopeMatchersProperties(p);
    assertThat(matchers, not(nullValue()));
    assertThat(matchers, empty());
    
  }
  
  @Test
  public void testParsing() {
    
    MatcherProperties regex = new MatcherProperties();
    regex.setType(MatcherType.regexp);
    regex.setName("WLCG scope");
    regex.setRegexp("^wlcg$");
    
    MatcherProperties path = new MatcherProperties();
    path.setType(MatcherType.path);
    path.setName("storage.read");
    path.setPrefix("storage.read");
    path.setPath("/");
    
    p.setMatchers(asList(regex,path));
    
    ScopeMatchersPropertiesParser parser = new ScopeMatchersPropertiesParser();
    Set<ScopeMatcher> matchers = parser.parseScopeMatchersProperties(p);
    assertThat(matchers, not(nullValue()));
    assertThat(matchers, hasSize(2));
    
    assertThat(matchers, hasItem(structuredPathMatcher("storage.read", "/")));
    assertThat(matchers, hasItem(regexpMatcher("^wlcg$")));
  }

}
