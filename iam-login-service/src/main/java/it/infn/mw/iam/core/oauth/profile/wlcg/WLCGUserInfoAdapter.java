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



import static java.util.Objects.isNull;

import org.mitre.openid.connect.model.UserInfo;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import it.infn.mw.iam.core.userinfo.DelegateUserInfoAdapter;

public class WLCGUserInfoAdapter extends DelegateUserInfoAdapter {

  private static final long serialVersionUID = 1L;

  private final String[] resolvedGroups;

  private WLCGUserInfoAdapter(UserInfo delegate, String[] resolvedGroups) {
    super(delegate);
    this.resolvedGroups = resolvedGroups;
  }

  @Override
  public JsonObject toJson() {
    JsonObject json = super.toJson();

    json.remove("groups");
    json.remove("organisation_name");

    if (!isNull(resolvedGroups)) {
      JsonArray groups = new JsonArray();
      for (String g : resolvedGroups) {
        groups.add(new JsonPrimitive(g));
      }
      json.add("wlcg.groups", groups);
    }

    return json;
  }

  public static WLCGUserInfoAdapter forUserInfo(UserInfo delegate, String[] resolvedGroups) {
    return new WLCGUserInfoAdapter(delegate, resolvedGroups);
  }

  public static WLCGUserInfoAdapter forUserInfo(UserInfo delegate) {
    return new WLCGUserInfoAdapter(delegate, null);
  }
}
