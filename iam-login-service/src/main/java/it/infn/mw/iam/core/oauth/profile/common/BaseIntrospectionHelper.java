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
package it.infn.mw.iam.core.oauth.profile.common;

import java.util.Set;
import java.util.stream.Collectors;

import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.service.IntrospectionResultAssembler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.Sets;

import it.infn.mw.iam.core.oauth.profile.IntrospectionResultHelper;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcher;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcherRegistry;

public abstract class BaseIntrospectionHelper implements IntrospectionResultHelper {

  public static final Logger LOG = LoggerFactory.getLogger(BaseIntrospectionHelper.class);

  private final IntrospectionResultAssembler assembler;
  private final ScopeMatcherRegistry scopeMatchersRegistry;

  public BaseIntrospectionHelper(IntrospectionResultAssembler assembler,
      ScopeMatcherRegistry scopeMatchersRegistry) {
    this.assembler = assembler;
    this.scopeMatchersRegistry = scopeMatchersRegistry;
  }

  public IntrospectionResultAssembler getAssembler() {
    return assembler;
  }

  public ScopeMatcherRegistry getScopeMatchersRegistry() {
    return scopeMatchersRegistry;
  }

  protected Set<String> filterScopes(OAuth2AccessTokenEntity accessToken, Set<String> authScopes) {

    Set<ScopeMatcher> matchers = authScopes.stream()
      .map(getScopeMatchersRegistry()::findMatcherForScope)
      .collect(Collectors.toSet());

    Set<String> filteredScopes = Sets.newHashSet();

    // We must use for loop here since streams are not supported
    // by this version of EclipseLink on entity collections
    for (String accessTokenScope : accessToken.getScope()) {
      if (matchers.stream().anyMatch(m -> m.matches(accessTokenScope))) {
        filteredScopes.add(accessTokenScope);
      }
    }

    return filteredScopes;
  }

}
