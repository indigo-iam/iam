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

import static java.util.stream.Collectors.joining;
import static org.mitre.oauth2.service.IntrospectionResultAssembler.SCOPE;

import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.service.IntrospectionResultAssembler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.Sets;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.profile.IntrospectionResultHelper;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcher;
import it.infn.mw.iam.core.oauth.scope.matchers.ScopeMatcherRegistry;

public abstract class BaseIntrospectionHelper implements IntrospectionResultHelper {

  public static final Logger LOG = LoggerFactory.getLogger(BaseIntrospectionHelper.class);

  public static final String PROFILE = "profile";
  public static final String AUDIENCE = "aud";
  public static final String NAME = "name";
  public static final String GIVEN_NAME = "given_name";
  public static final String FAMILY_NAME = "family_name";
  public static final String PREFERRED_USERNAME = "preferred_username";
  public static final String EMAIL = "email";
  public static final String GROUPS = "groups";
  public static final String ORGANISATION_NAME = "organisation_name";
  public static final String ISSUER = "iss";
  public static final String EDUPERSON_SCOPED_AFFILIATION = "eduperson_scoped_affiliation";
  public static final String EDUPERSON_ENTITLEMENT = "eduperson_entitlement";

  private final IamProperties properties;
  private final IntrospectionResultAssembler assembler;
  private final ScopeMatcherRegistry scopeMatchersRegistry;

  public BaseIntrospectionHelper(IamProperties props, IntrospectionResultAssembler assembler,
      ScopeMatcherRegistry scopeMatchersRegistry) {
    this.properties = props;
    this.assembler = assembler;
    this.scopeMatchersRegistry = scopeMatchersRegistry;
  }

  public IamProperties getProperties() {
    return properties;
  }

  public IntrospectionResultAssembler getAssembler() {
    return assembler;
  }

  public ScopeMatcherRegistry getScopeMatchersRegistry() {
    return scopeMatchersRegistry;
  }

  protected void addScopeClaim(Map<String, Object> introspectionResult, Set<String> scopes) {
    if (!scopes.isEmpty()) {
      introspectionResult.put(SCOPE, scopes.stream().collect(joining(" ")));
    }
  }

  protected void addIssuerClaim(Map<String, Object> introspectionResult) {
    final String oidcIssuer = getProperties().getIssuer();
    String trailingSlashIssuer = oidcIssuer.endsWith("/") ? oidcIssuer : oidcIssuer + "/";

    introspectionResult.put(ISSUER, trailingSlashIssuer);
  }

  protected void addAudience(Map<String, Object> introspectionResult,
      OAuth2AccessTokenEntity accessToken) {

    try {

      List<String> audience = accessToken.getJwt().getJWTClaimsSet().getAudience();

      if (audience != null && !audience.isEmpty()) {
        introspectionResult.put(AUDIENCE, audience.stream().collect(joining(" ")));
      }

    } catch (ParseException e) {
      LOG.error("Error getting audience out of access token: {}", e.getMessage(), e);
    }

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
