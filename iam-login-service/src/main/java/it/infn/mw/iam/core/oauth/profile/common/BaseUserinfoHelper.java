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

import org.mitre.openid.connect.model.UserInfo;
import org.mitre.openid.connect.service.UserInfoService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.profile.UserInfoHelper;

@SuppressWarnings("deprecation")
public abstract class BaseUserinfoHelper implements UserInfoHelper {

  private final IamProperties properties;
  private final UserInfoService userInfoService;

  public BaseUserinfoHelper(IamProperties props, UserInfoService userInfoService) {
    this.properties = props;
    this.userInfoService = userInfoService;
  }

  public IamProperties getProperties() {
    return properties;
  }

  public UserInfoService getUserInfoService() {
    return userInfoService;
  }

  protected UserInfo lookupUserinfo(OAuth2Authentication authentication) {
    final String username = authentication.getName();

    return getUserInfoService().getByUsername(username);
  }

}
