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

import static it.infn.mw.iam.core.oauth.scope.matchers.StringEqualsScopeMatcher.stringEqualsMatcher;

import it.infn.mw.iam.api.scim.exception.IllegalArgumentException;
import it.infn.mw.iam.core.oauth.scope.matchers.RegexpScopeMatcher;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcher;
import it.infn.mw.iam.core.oauth.scope.matchers.StructuredPathScopeMatcher;
import it.infn.mw.iam.persistence.model.IamScopePolicy;
import it.infn.mw.iam.persistence.model.IamTokenExchangeScopePolicy;
import it.infn.mw.iam.persistence.model.PolicyRule;

public class ScopeExchangePolicy {

  final PolicyRule rule;

  final ScopeMatcher matcher;

  private ScopeExchangePolicy(PolicyRule rule, ScopeMatcher matcher) {
    this.rule = rule;
    this.matcher = matcher;
  }

  public boolean deniesScope(String scope) {
    return appliesToScope(scope) && PolicyRule.DENY.equals(rule);
  }
  
  public boolean permitsScope(String scope) {
    return appliesToScope(scope) && PolicyRule.PERMIT.equals(rule);
  }

  public boolean appliesToScope(String scope) {
    return matcher.matches(scope);
  }

  public PolicyRule rule() {
    return rule;
  }

  public ScopeMatcher matcher() {
    return matcher;
  }

  public static ScopeExchangePolicy fromEntity(IamTokenExchangeScopePolicy sp) {
    ScopeMatcher matcher;
    if (sp.getType().equals(IamScopePolicy.MatchingPolicy.EQ)) {
      matcher = stringEqualsMatcher(sp.getMatchParam());
    } else if (sp.getType().equals(IamScopePolicy.MatchingPolicy.PATH)) {
      matcher = StructuredPathScopeMatcher.fromString(sp.getMatchParam());
    } else if (sp.getType().equals(IamScopePolicy.MatchingPolicy.REGEXP)) {
      matcher = RegexpScopeMatcher.regexpMatcher(sp.getMatchParam());
    } else {
      throw new IllegalArgumentException("Unsupported scope matcher type: " + sp.getType());
    }
    return new ScopeExchangePolicy(sp.getRule(), matcher);
  }

}
