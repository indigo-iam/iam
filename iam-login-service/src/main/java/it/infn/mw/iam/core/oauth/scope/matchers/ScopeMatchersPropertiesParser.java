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
package it.infn.mw.iam.core.oauth.scope.matchers;

import static it.infn.mw.iam.core.oauth.scope.matchers.RegexpScopeMatcher.regexpMatcher;
import static it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatchersProperties.MatcherProperties.MatcherType.regexp;
import static it.infn.mw.iam.core.oauth.scope.matchers.StructuredPathScopeMatcher.structuredPathMatcher;
import static java.util.stream.Collectors.toSet;

import java.util.Set;

import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatchersProperties.MatcherProperties;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatchersProperties.MatcherProperties.MatcherType;

public class ScopeMatchersPropertiesParser {

  private ScopeMatcher parseProperties(MatcherProperties p) {
    if (regexp.equals(p.getType())) {
      return regexpMatcher(p.getRegexp());
    } else if (MatcherType.path.equals(p.getType())) {
      return structuredPathMatcher(p.getPrefix(), p.getPath());
    } else {
      throw new IllegalArgumentException("Unsupported matcher type: " + p.getType());
    }
  }

  public Set<ScopeMatcher> parseScopeMatchersProperties(ScopeMatchersProperties props) {
    return props.getMatchers().stream().map(this::parseProperties).collect(toSet());
  }

}
