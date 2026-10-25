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
package it.infn.mw.iam.test.oauth.profile;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.TokenRequest;

import it.infn.mw.iam.core.oauth.profile.wlcg.WlcgScopeOrder;

@SuppressWarnings("deprecation")
class WlcgScopeOrderTests {

  @Test
  void preservesRequestedOrderAndFiltersUnauthorizedScopes() {

    Set<String> authorized = Set.of("wlcg.groups:/a", "wlcg.groups:/b", "wlcg");
    assertThat(
        WlcgScopeOrder.fromRaw("wlcg.groups:/b wlcg.groups:/unknown wlcg.groups:/a", authorized))
          .containsExactly("wlcg.groups:/b", "wlcg.groups:/a", "wlcg");
  }

  @Test
  void removesDuplicatesAndHandlesLegacyRequests() {

    Set<String> authorized = new LinkedHashSet<>(Set.of("wlcg.groups:/b", "wlcg.groups:/a"));
    assertThat(WlcgScopeOrder.fromRaw("wlcg.groups:/b wlcg.groups:/b", authorized))
      .containsExactly("wlcg.groups:/b", "wlcg.groups:/a");
    assertThat(WlcgScopeOrder.fromRaw(null, authorized)).containsExactly("wlcg.groups:/a",
        "wlcg.groups:/b");
  }

  @Test
  void normalAuthorizationUsesOriginalScopeParameter() {

    OAuth2Authentication authentication =
        authentication(false, Map.of("scope", "wlcg.groups:/b wlcg.groups:/a"), null);

    assertThat(WlcgScopeOrder.forAuthentication(authentication,
        Set.of("wlcg.groups:/a", "wlcg.groups:/b"))).containsExactly("wlcg.groups:/b",
            "wlcg.groups:/a");
  }

  @Test
  void refreshWithExplicitScopesUsesRefreshRequestOrder() {

    OAuth2Authentication authentication =
        authentication(true, Map.of("scope", "wlcg.groups:/a wlcg.groups:/b"),
            Map.of("scope", "wlcg.groups:/b wlcg.groups:/a"));

    assertThat(WlcgScopeOrder.forAuthentication(authentication,
        Set.of("wlcg.groups:/a", "wlcg.groups:/b"))).containsExactly("wlcg.groups:/b",
            "wlcg.groups:/a");
  }

  @Test
  void refreshWithoutExplicitScopesFallsBackToOriginalRequestOrder() {

    OAuth2Authentication authentication =
        authentication(true, Map.of("scope", "wlcg.groups:/b wlcg.groups:/a"), Map.of());

    assertThat(WlcgScopeOrder.forAuthentication(authentication,
        Set.of("wlcg.groups:/a", "wlcg.groups:/b"))).containsExactly("wlcg.groups:/b",
            "wlcg.groups:/a");
  }

  @Test
  void refreshWithoutRefreshTokenRequestUsesOriginalRequestOrder() {

    OAuth2Authentication authentication =
        authentication(true, Map.of("scope", "wlcg.groups:/b wlcg.groups:/a"), null);

    assertThat(WlcgScopeOrder.forAuthentication(authentication,
        Set.of("wlcg.groups:/a", "wlcg.groups:/b"))).containsExactly("wlcg.groups:/b",
            "wlcg.groups:/a");
  }

  @Test
  void missingScopeParametersUseDeterministicFallback() {

    OAuth2Authentication authentication = authentication(false, Map.of(), null);

    assertThat(WlcgScopeOrder.forAuthentication(authentication,
        Set.of("wlcg.groups:/b", "wlcg.groups:/a"))).containsExactly("wlcg.groups:/a",
            "wlcg.groups:/b");
  }

  @Test
  void nullRequestParametersUseDeterministicFallback() {

    OAuth2Authentication authentication = authentication(false, null, null);

    assertThat(WlcgScopeOrder.forAuthentication(authentication,
        Set.of("wlcg.groups:/b", "wlcg.groups:/a"))).containsExactly("wlcg.groups:/a",
            "wlcg.groups:/b");
  }

  @Test
  void whitespaceAndEmptyScopeStringUseDeterministicFallback() {

    Set<String> authorized = Set.of("wlcg.groups:/b", "wlcg.groups:/a");

    assertThat(WlcgScopeOrder.fromRaw("   ", authorized)).containsExactly("wlcg.groups:/a",
        "wlcg.groups:/b");
    assertThat(WlcgScopeOrder.fromRaw("\t wlcg.groups:/b \n wlcg.groups:/a   ", authorized))
      .containsExactly("wlcg.groups:/b", "wlcg.groups:/a");
  }

  @Test
  void supportsLongScopesAndEmptyAuthorizedScopes() {

    String longScope = "storage.read:/" + "a".repeat(5000);
    assertThat(WlcgScopeOrder.fromRaw(longScope, Set.of(longScope))).containsExactly(longScope);
    assertThat(WlcgScopeOrder.fromRaw("wlcg.groups:/a", Set.of())).isEmpty();
  }

  @Test
  void serializesScopesInIterationOrder() {

    LinkedHashSet<String> ordered = new LinkedHashSet<>();
    ordered.add("wlcg.groups:/b");
    ordered.add("wlcg.groups:/a");

    assertThat(WlcgScopeOrder.serialize(ordered)).isEqualTo("wlcg.groups:/b wlcg.groups:/a");
    assertThat(WlcgScopeOrder.serialize(Set.of())).isEmpty();
  }

  private static OAuth2Authentication authentication(boolean refresh,
      Map<String, String> requestParameters, Map<String, String> refreshParameters) {

    OAuth2Request request = mock(OAuth2Request.class);
    when(request.isRefresh()).thenReturn(refresh);
    when(request.getRequestParameters()).thenReturn(requestParameters);
    if (refresh && refreshParameters != null) {
      TokenRequest refreshRequest = mock(TokenRequest.class);
      when(refreshRequest.getRequestParameters()).thenReturn(refreshParameters);
      when(request.getRefreshTokenRequest()).thenReturn(refreshRequest);
    }
    OAuth2Authentication authentication = mock(OAuth2Authentication.class);
    when(authentication.getOAuth2Request()).thenReturn(request);
    return authentication;
  }
}
