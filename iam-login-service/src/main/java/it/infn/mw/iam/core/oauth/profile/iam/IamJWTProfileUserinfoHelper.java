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
package it.infn.mw.iam.core.oauth.profile.iam;

import static it.infn.mw.iam.authn.util.AuthenticationUtils.isSupportedExternalAuthenticationToken;
import static java.util.Objects.isNull;

import java.util.Map;

import org.mitre.openid.connect.model.UserInfo;
import org.mitre.openid.connect.service.UserInfoService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import it.infn.mw.iam.authn.ExternalAuthenticationInfoProcessor;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.profile.common.BaseUserinfoHelper;
import it.infn.mw.iam.core.userinfo.IamDecoratedUserInfo;

@SuppressWarnings("deprecation")
public class IamJWTProfileUserinfoHelper extends BaseUserinfoHelper {

  private final ExternalAuthenticationInfoProcessor extAuthnProcessor;

  public IamJWTProfileUserinfoHelper(IamProperties props, UserInfoService userInfoService,
      ExternalAuthenticationInfoProcessor proc) {
    super(props, userInfoService);
    this.extAuthnProcessor = proc;
  }

  @Override
  public UserInfo resolveUserInfo(OAuth2Authentication authentication) {

    UserInfo ui = lookupUserinfo(authentication);

    if (isNull(ui)) {
      return null;
    }
    
    IamDecoratedUserInfo dui = IamDecoratedUserInfo.forUser(ui);
    dui.setOrganisationName(getProperties().getOrganisation().getName());

    if (isSupportedExternalAuthenticationToken(authentication.getUserAuthentication())) {
      Map<String, String> processedAuthInfo = extAuthnProcessor.process(authentication);
      if (!processedAuthInfo.isEmpty()) {
        dui.setAuthenticationInfo(processedAuthInfo);
      }
    }

    return dui;
  }
}
