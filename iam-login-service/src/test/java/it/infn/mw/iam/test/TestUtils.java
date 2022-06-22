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
package it.infn.mw.iam.test;

import static io.restassured.RestAssured.given;

import java.util.ArrayList;
import java.util.List;

import org.springframework.http.HttpStatus;

import io.restassured.specification.RequestSpecification;
import it.infn.mw.iam.api.scim.model.ScimMemberRef;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.test.util.RestAssuredJacksonUtils;

public class TestUtils {

  public static final int TOTAL_USERS_COUNT = 254;
  public static final String CLIENT_CRED_GRANT_CLIENT_ID = "client-cred";
  public static final String CLIENT_CRED_GRANT_CLIENT_SECRET = "secret";
  public static final String PASSWORD_GRANT_CLIENT_ID = "password-grant";
  public static final String PASSWORD_GRANT_CLIENT_SECRET = "secret";

  public static void initRestAssured() {
    RestAssuredJacksonUtils.initRestAssured();
  }

  public static ScimMemberRef getMemberRef(ScimUser user) {

    return ScimMemberRef.builder()
      .display(user.getDisplayName())
      .ref(user.getMeta().getLocation())
      .value(user.getId())
      .build();
  }

  public static List<ScimMemberRef> buildScimMemberRefList(List<ScimUser> users) {

    List<ScimMemberRef> membersRefs = new ArrayList<ScimMemberRef>();
    for (ScimUser u : users) {
      membersRefs.add(getMemberRef(u));
    }
    return membersRefs;
  }

  public static String getAccessToken(String clientId, String clientSecret, String scope) {
    return clientCredentialsTokenGetter(clientId, clientSecret).scope(scope).getAccessToken();
  }

  public static AccessTokenGetter clientCredentialsTokenGetter(String clientId,
      String clientSecret) {
    return new AccessTokenGetter(clientId, clientSecret).grantType("client_credentials");
  }

  public static AccessTokenGetter clientCredentialsTokenGetter() {
    return new AccessTokenGetter(CLIENT_CRED_GRANT_CLIENT_ID, CLIENT_CRED_GRANT_CLIENT_SECRET)
      .grantType("client_credentials");
  }


  public static AccessTokenGetter passwordTokenGetter() {
    return new AccessTokenGetter(PASSWORD_GRANT_CLIENT_ID, PASSWORD_GRANT_CLIENT_SECRET)
      .grantType("password");
  }

  public static AccessTokenGetter passwordTokenGetter(String clientId, String clientSecret) {
    return new AccessTokenGetter(clientId, clientSecret).grantType("password");
  }

  public static class AccessTokenGetter {
    private String clientId;
    private String clientSecret;
    private String scope;
    private String grantType;
    private String username;
    private String password;
    private String audience;

    private int port = 8080;

    public AccessTokenGetter(String clientId, String clientSecret) {
      this.clientId = clientId;
      this.clientSecret = clientSecret;
    }

    public AccessTokenGetter scope(String scope) {
      this.scope = scope;
      return this;
    }

    public AccessTokenGetter grantType(String grantType) {
      this.grantType = grantType;
      return this;
    }

    public AccessTokenGetter username(String username) {
      this.username = username;
      return this;
    }

    public AccessTokenGetter password(String password) {
      this.password = password;
      return this;
    }

    public AccessTokenGetter audience(String audience) {
      this.audience = audience;
      return this;
    }

    public AccessTokenGetter port(int port) {
      this.port = port;
      return this;
    }

    public String getAccessToken() {

      RequestSpecification req = given().port(port)
        .param("grant_type", grantType)
        .param("client_id", clientId)
        .param("client_secret", clientSecret)
        .param("scope", scope);

      if (audience != null) {
        req.param("aud", audience);
      }

      if ("password".equals(grantType)) {
        req.param("username", username).param("password", password);
      }

      return req.when()
        .post("/token")
        .then()
        .statusCode(HttpStatus.OK.value())
        .extract()
        .path("access_token");
    }
  }
}
