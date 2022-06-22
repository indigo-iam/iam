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
package it.infn.mw.iam.core.userinfo;

import static java.util.Objects.isNull;

import java.util.Map;

import org.mitre.openid.connect.model.UserInfo;

import com.google.gson.JsonObject;

public class IamDecoratedUserInfo extends DelegateUserInfoAdapter implements DecoratedUserInfo {

  public static final String ORGANISATION_NAME_CLAIM = "organisation_name";
  public static final String EXTERNAL_AUTHN_CLAIM = "external_authn";

  private static final long serialVersionUID = 1L;

  private String organisationName;

  private Map<String, String> authenticationInfo;

  private IamDecoratedUserInfo(UserInfo delegate) {
    super(delegate);
  }

  @Override
  public JsonObject toJson() {

    JsonObject userInfo = super.toJson();

    userInfo.addProperty(ORGANISATION_NAME_CLAIM, organisationName);

    if (!isNull(authenticationInfo)) {
      JsonObject extAuthn = new JsonObject();
      for (Map.Entry<String, String> e : authenticationInfo.entrySet()) {
        extAuthn.addProperty(e.getKey(), e.getValue());
      }
      userInfo.add(EXTERNAL_AUTHN_CLAIM, extAuthn);
    }

    return userInfo;

  }

  @Override
  public String getOrganisationName() {
    return organisationName;
  }

  @Override
  public Map<String, String> getAuthenticationInfo() {
    return authenticationInfo;
  }


  public static IamDecoratedUserInfo forUser(UserInfo u) {
    return new IamDecoratedUserInfo(u);
  }

  public void setOrganisationName(String organisationName) {
    this.organisationName = organisationName;
  }

  public void setAuthenticationInfo(Map<String, String> authenticationInfo) {
    this.authenticationInfo = authenticationInfo;
  }

}
