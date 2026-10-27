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
package it.infn.mw.iam.test.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.util.OAuth2Utils;

import it.infn.mw.iam.core.oauth.AuthorizationRequestBuilder;
import it.infn.mw.iam.core.oauth.profile.wlcg.WlcgGroupHelper;
import it.infn.mw.iam.core.oauth.scope.pdp.ScopeFilter;
import it.infn.mw.iam.persistence.model.IamGroup;

@SuppressWarnings("deprecation")
class AuthorizationRequestBuilderScopeOrderTests {

  @Test
  void preservesDefaultGroupsBeforeExplicitOptionalGroup() {

    ScopeFilter filter = mock(ScopeFilter.class);
    Authentication authentication = mock(Authentication.class);
    AuthorizationRequestBuilder builder = new AuthorizationRequestBuilder(null, filter, null);
    Map<String, String> parameters = new HashMap<>();
    parameters.put("scope", "wlcg wlcg.groups wlcg.groups:/Optional");

    // Deliberately return a different order, independently of HashSet iteration details.
    when(filter.filterScopes(Set.of("wlcg", "wlcg.groups", "wlcg.groups:/Optional"), authentication,
        "client"))
          .thenReturn(new LinkedHashSet<>(List.of("wlcg.groups:/Optional", "wlcg.groups", "wlcg")));

    builder.filterRequestedScopes(parameters, authentication, "client");

    assertEquals("wlcg wlcg.groups wlcg.groups:/Optional", parameters.get("scope"));
    assertEquals("wlcg wlcg.groups wlcg.groups:/Optional",
        builder.build(parameters).getRequestParameters().get("scope"));

    IamGroup analysis = group("Analysis");
    IamGroup production = group("Production");
    IamGroup optional = group("Optional");
    optional.setLabels(Set.of(WlcgGroupHelper.OPTIONAL_GROUP_LABEL));

    assertThat(WlcgGroupHelper.resolveGroupNames(
        new LinkedHashSet<>(List.of(parameters.get("scope").split(" "))),
        Set.of(analysis, production, optional))).containsExactly("/Analysis", "/Production",
            "/Optional");
  }

  @Test
  void preservesExplicitGroupOrderWithoutRestoringRejectedScopes() {

    ScopeFilter filter = mock(ScopeFilter.class);
    Authentication authentication = mock(Authentication.class);
    AuthorizationRequestBuilder builder = new AuthorizationRequestBuilder(null, filter, null);
    Map<String, String> parameters = new HashMap<>();
    parameters.put("scope", "wlcg wlcg.groups:/Optional wlcg.groups:/Denied wlcg.groups");
    Set<String> requested = OAuth2Utils.parseParameterList(parameters.get("scope"));

    when(filter.filterScopes(requested, authentication, "client"))
      .thenReturn(new LinkedHashSet<>(List.of("wlcg.groups", "wlcg", "wlcg.groups:/Optional")));

    builder.filterRequestedScopes(parameters, authentication, "client");

    assertEquals("wlcg wlcg.groups:/Optional wlcg.groups", parameters.get("scope"));
  }

  private static IamGroup group(String name) {
    IamGroup group = new IamGroup();
    group.setName(name);
    group.setUuid(name);
    return group;
  }
}
