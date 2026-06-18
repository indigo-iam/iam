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
package it.infn.mw.iam.core.oauth.profile.wlcg;

import java.util.Set;

import com.google.common.collect.Sets;

import it.infn.mw.iam.core.oauth.profile.iam.IamScopeClaimTranslationService;

public class WlcgScopeClaimTranslationService extends IamScopeClaimTranslationService {

  @Override
  public Set<String> getClaimsForScope(String scope) {

    if (WlcgOidcScopes.isWlcgScope(scope)) {
      return Sets.newHashSet(WlcgExtraClaimNames.WLCG_GROUPS, WlcgExtraClaimNames.WLCG_VER,
          WlcgExtraClaimNames.AUTH_TIME);
    }
    if (WlcgOidcScopes.isWlcgGroupScope(scope)) {
      return Sets.newHashSet(WlcgExtraClaimNames.WLCG_GROUPS, WlcgExtraClaimNames.WLCG_VER);
    }
    return super.getClaimsForScope(scope);
  }

}
