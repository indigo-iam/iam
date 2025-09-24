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

import static it.infn.mw.iam.core.oauth.profile.wlcg.WlcgExtraClaimNames.AUTH_TIME;
import static it.infn.mw.iam.core.oauth.profile.wlcg.WlcgExtraClaimNames.EDUPERSON_ASSURANCE;
import static it.infn.mw.iam.core.oauth.profile.wlcg.WlcgExtraClaimNames.WLCG_GROUPS;
import static it.infn.mw.iam.core.oauth.profile.wlcg.WlcgExtraClaimNames.WLCG_VER;

import org.mitre.openid.connect.service.ScopeClaimTranslationService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import it.infn.mw.iam.api.scim.converter.SshKeyConverter;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.attributes.AttributeMapHelper;
import it.infn.mw.iam.core.oauth.profile.aarc.AarcClaimValueHelper;
import it.infn.mw.iam.core.oauth.profile.iam.IamClaimValueHelper;
import it.infn.mw.iam.persistence.model.IamAccount;

@SuppressWarnings("deprecation")
public class WlcgClaimValueHelper extends IamClaimValueHelper {

  public WlcgClaimValueHelper(IamProperties properties, SshKeyConverter sshConverter,
      AttributeMapHelper attrHelper, ScopeClaimTranslationService scopeClaimTranslationService) {
    super(properties, sshConverter, attrHelper, scopeClaimTranslationService);
  }

  @Override
  public Object resolveClaim(String claimName, IamAccount account, OAuth2Authentication auth) {

    switch (claimName) {
      case WLCG_VER:
        return WlcgJWTProfile.PROFILE_VERSION;
      case WLCG_GROUPS:
        return account != null ? WlcgGroupHelper.resolveGroupNames(auth.getOAuth2Request().getScope(),
            account.getUserInfo().getGroups()) : null;
      case EDUPERSON_ASSURANCE:
        return AarcClaimValueHelper.DEFAULT_LOA;
      case AUTH_TIME:
        return account != null ? account.getLastLoginTime() : null;
      default:
        return super.resolveClaim(claimName, account, auth);
    }
  }
}
