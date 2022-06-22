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
package it.infn.mw.iam.core.oauth.profile.aarc;

import static java.util.Objects.isNull;

import org.mitre.openid.connect.model.UserInfo;
import org.mitre.openid.connect.service.UserInfoService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.profile.common.BaseUserinfoHelper;
import it.infn.mw.iam.core.userinfo.AarcDecoratedUserInfo;
import it.infn.mw.iam.persistence.model.IamUserInfo;
import it.infn.mw.iam.persistence.repository.UserInfoAdapter;

@SuppressWarnings("deprecation")
public class AarcJWTProfileUserinfoHelper extends BaseUserinfoHelper {

  protected final AarcClaimValueHelper claimValueHelper;

  public AarcJWTProfileUserinfoHelper(IamProperties props, UserInfoService userInfoService,
      AarcClaimValueHelper claimValueHelper) {
    super(props, userInfoService);
    this.claimValueHelper = claimValueHelper;
  }

  @Override
  public UserInfo resolveUserInfo(OAuth2Authentication authentication) {

    UserInfo ui = lookupUserinfo(authentication);

    if (isNull(ui)) {
      return null;
    }

    IamUserInfo iamUserInfo = ((UserInfoAdapter) ui).getUserinfo();

    AarcDecoratedUserInfo aui = AarcDecoratedUserInfo.forUser(ui);
    aui.setScopedAffiliation(getProperties().getOrganisation().getName());
    aui.setEntitlements(claimValueHelper.resolveGroups(iamUserInfo));

    return aui;
  }

}
