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
package it.infn.mw.iam.test.api.account.multi_factor_authentication;

import static it.infn.mw.iam.test.TestUtils.passwordTokenGetter;
import static org.hamcrest.Matchers.equalTo;

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.junit4.SpringRunner;

import io.restassured.RestAssured;
import io.restassured.response.ValidatableResponse;
import it.infn.mw.iam.api.account.multi_factor_authentication.MultiFactorSettingsController;
import it.infn.mw.iam.api.scim.model.ScimEmail;
import it.infn.mw.iam.api.scim.model.ScimName;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.provisioning.ScimUserProvisioning;
import it.infn.mw.iam.test.TestUtils;
import it.infn.mw.iam.test.util.annotation.IamRandomPortIntegrationTest;

@RunWith(SpringRunner.class)
@IamRandomPortIntegrationTest
public class MultiFactorSettingsTests {

  @Value("${local.server.port}")
  private Integer iamPort;

  private ScimUser testUser;

  private final String USER_USERNAME = "test_user";
  private final String USER_PASSWORD = "password";
  private final ScimName USER_NAME =
      ScimName.builder().givenName("TESTER").familyName("USER").build();
  private final ScimEmail USER_EMAIL = ScimEmail.builder().email("test_user@test.org").build();

  @Autowired
  private ScimUserProvisioning userService;

  @BeforeClass
  public static void init() {
    TestUtils.initRestAssured();
  }

  @Before
  public void setup() {
    testUser = userService.create(ScimUser.builder()
      .active(true)
      .addEmail(USER_EMAIL)
      .name(USER_NAME)
      .displayName(USER_USERNAME)
      .userName(USER_USERNAME)
      .password(USER_PASSWORD)
      .build());
  }

  @After
  public void tearDown() {
    userService.delete(testUser.getId());
  }

  private ValidatableResponse doGet(String accessToken) {
    return RestAssured.given()
      .port(iamPort)
      .auth()
      .preemptive()
      .oauth2(accessToken)
      .log()
      .all(true)
      .when()
      .get(MultiFactorSettingsController.MULTI_FACTOR_SETTINGS_URL)
      .then()
      .log()
      .all(true);
  }

  private ValidatableResponse doGet() {
    return RestAssured.given()
      .port(iamPort)
      .log()
      .all(true)
      .when()
      .get(MultiFactorSettingsController.MULTI_FACTOR_SETTINGS_URL)
      .then()
      .log()
      .all(true);
  }

  @Test
  public void testGetSettings() throws Exception {
    String accessToken = passwordTokenGetter().port(iamPort)
      .username(testUser.getUserName())
      .password(USER_PASSWORD)
      .getAccessToken();

    doGet(accessToken).statusCode(HttpStatus.OK.value());
  }

  @Test
  public void testGetSettingsFullAuthenticationRequired() {
    doGet().statusCode(HttpStatus.UNAUTHORIZED.value())
      .body("error", equalTo("unauthorized"))
      .body("error_description",
          equalTo("Full authentication is required to access this resource"));
  }
}
