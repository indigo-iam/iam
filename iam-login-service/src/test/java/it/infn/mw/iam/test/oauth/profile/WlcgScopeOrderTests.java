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

import java.util.LinkedHashSet;
import java.util.Set;

import org.junit.jupiter.api.Test;

import it.infn.mw.iam.core.oauth.profile.wlcg.WlcgScopeOrder;

class WlcgScopeOrderTests {

  @Test
  void preservesRequestedOrderAndFiltersUnauthorizedScopes() throws Exception {
    Set<String> authorized = Set.of("wlcg.groups:/a", "wlcg.groups:/b", "wlcg");
    assertThat(
        WlcgScopeOrder.fromRaw("wlcg.groups:/b wlcg.groups:/unknown wlcg.groups:/a", authorized))
          .containsExactly("wlcg.groups:/b", "wlcg.groups:/a", "wlcg");
  }

  @Test
  void removesDuplicatesAndHandlesLegacyRequests() throws Exception {
    Set<String> authorized = new LinkedHashSet<>(Set.of("wlcg.groups:/b", "wlcg.groups:/a"));
    assertThat(WlcgScopeOrder.fromRaw("wlcg.groups:/b wlcg.groups:/b", authorized))
      .containsExactly("wlcg.groups:/b", "wlcg.groups:/a");
    assertThat(WlcgScopeOrder.fromRaw(null, authorized)).containsExactly("wlcg.groups:/a",
        "wlcg.groups:/b");
  }
}
