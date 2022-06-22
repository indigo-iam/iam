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

import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.Matchers.nullValue;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.restassured.RestAssured;
import it.infn.mw.iam.test.TestUtils;
import it.infn.mw.iam.test.util.annotation.IamRandomPortIntegrationTest;

@RunWith(SpringRunner.class)
@IamRandomPortIntegrationTest
@TestPropertySource(properties = {
// @formatter:off
    "iam.jwt-profile.default-profile=wlcg",
    "scope.matchers[0].name=storage.read",
    "scope.matchers[0].type=path",
    "scope.matchers[0].prefix=storage.read",
    "scope.matchers[0].path=/",
    "scope.matchers[1].name=storage.write",
    "scope.matchers[1].type=path",
    "scope.matchers[1].prefix=storage.write",
    "scope.matchers[1].path=/",
    "scope.matchers[2].name=wlcg.groups",
    "scope.matchers[2].type=regexp",
    "scope.matchers[2].regexp=^wlcg\\.groups(?::((?:\\/[a-zA-Z0-9][a-zA-Z0-9_.-]*)+))?$",
    // @formatter:on
})
public class WLCGProfileUserinfoEndpointTests {

  private static final String USERNAME = "test";
  private static final String PASSWORD = "password";
  private static final String USERINFO_URL_TEMPLATE = "http://localhost:%d/userinfo";

  @Value("${local.server.port}")
  private Integer iamPort;

  private String userinfoUrl;

  @Autowired
  ObjectMapper mapper;

  @BeforeClass
  public static void init() {
    TestUtils.initRestAssured();
  }

  @Before
  public void setup() {
    RestAssured.enableLoggingOfRequestAndResponseIfValidationFails();
    RestAssured.port = iamPort;
    userinfoUrl = String.format(USERINFO_URL_TEMPLATE, iamPort);
  }

  @Test
  public void testUserinfoResponseWithGroups() {
    String accessToken = TestUtils.passwordTokenGetter()
      .port(iamPort)
      .username(USERNAME)
      .password(PASSWORD)
      .scope("openid profile wlcg.groups")
      .getAccessToken();

    RestAssured.given()
      .header("Authorization", String.format("Bearer %s", accessToken))
      .when()
      .get(userinfoUrl)
      .then()
      .statusCode(HttpStatus.OK.value())
      .body("\"wlcg.groups\"", hasItems("/Analysis", "/Production"));
  }

  @Test
  public void testUserinfoResponseWithoutGroups() {
    String accessToken = TestUtils.passwordTokenGetter()
      .port(iamPort)
      .username(USERNAME)
      .password(PASSWORD)
      .scope("openid profile")
      .getAccessToken();

    RestAssured.given()
      .header("Authorization", String.format("Bearer %s", accessToken))
      .when()
      .get(userinfoUrl)
      .then()
      .statusCode(HttpStatus.OK.value())
      .body("\"wlcg.groups\"", nullValue());
  }

}
