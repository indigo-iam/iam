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
package it.infn.mw.iam.test.oauth.client_registration;

import java.util.Set;

import com.google.common.base.Joiner;
import com.google.common.collect.Sets;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;

import it.infn.mw.iam.test.util.TokenGetterUtils;

public class ClientRegistrationTestSupport extends TokenGetterUtils {

  public static final String LEGACY_REGISTER_ENDPOINT = "/register";

  public static class ClientJsonStringBuilder {

    static final Joiner JOINER = Joiner.on(" ");

    String clientId = null;
    String name = "test_client";
    Set<String> redirectUris = Sets.newHashSet("http://localhost:9090");
    Set<String> grantTypes = Sets.newHashSet("client_credentials");
    Set<String> scopes = Sets.newHashSet();
    Set<String> responseTypes = Sets.newHashSet();
    Integer accessTokenValiditySeconds = null;
    Integer refreshTokenValiditySeconds = null;

    private ClientJsonStringBuilder() {}

    public static ClientJsonStringBuilder builder() {
      return new ClientJsonStringBuilder();
    }

    public ClientJsonStringBuilder clientId(String clientId) {
      this.clientId = clientId;
      return this;
    }

    public ClientJsonStringBuilder name(String name) {
      this.name = name;
      return this;
    }

    public ClientJsonStringBuilder redirectUris(String... uris) {
      this.redirectUris = Sets.newHashSet(uris);
      return this;
    }

    public ClientJsonStringBuilder grantTypes(String... grantTypes) {
      this.grantTypes = Sets.newHashSet(grantTypes);
      return this;
    }

    public ClientJsonStringBuilder scopes(String... scopes) {
      this.scopes = Sets.newHashSet(scopes);
      return this;
    }

    public ClientJsonStringBuilder responseTypes(String... responseTypes) {
      this.responseTypes = Sets.newHashSet(responseTypes);
      return this;
    }

    public ClientJsonStringBuilder accessTokenValiditySeconds(Integer accessTokenValiditySeconds) {
      this.accessTokenValiditySeconds = accessTokenValiditySeconds;
      return this;
    }

    public ClientJsonStringBuilder refreshTokenValiditySeconds(
        Integer refreshTokenValiditySeconds) {
      this.refreshTokenValiditySeconds = refreshTokenValiditySeconds;
      return this;
    }

    public String build() {
      JsonObject json = new JsonObject();
      json.addProperty("client_id", clientId);
      json.addProperty("client_name", name);
      json.addProperty("scope", JOINER.join(scopes));
      json.add("redirect_uris", getAsArray(redirectUris));
      json.add("grant_types", getAsArray(grantTypes));
      json.add("response_types", getAsArray(responseTypes, true));
      json.add("claims_redirect_uris", getAsArray(Sets.newHashSet(), true));
      json.add("request_uris", getAsArray(Sets.newHashSet(), true));
      json.add("contacts", getAsArray(Sets.newHashSet("test@iam.test")));
      json.addProperty("access_token_validity_seconds", accessTokenValiditySeconds);
      json.addProperty("refresh_token_validity_seconds", refreshTokenValiditySeconds);
      return json.toString();
    }

  }

  protected String setToString(Set<String> scopes) {
    Joiner joiner = Joiner.on(" ");
    return joiner.join(scopes);
  }

  public static JsonElement getAsArray(Set<String> value) {
    return getAsArray(value, false);
  }

  public static JsonElement getAsArray(Set<String> value, boolean preserveEmpty) {
    if (!preserveEmpty && value != null && value.isEmpty()) {
      return JsonNull.INSTANCE;
    }
    Gson gson = new Gson();
    return gson.toJsonTree(value, new TypeToken<Set<String>>() {}.getType());
  }

}
