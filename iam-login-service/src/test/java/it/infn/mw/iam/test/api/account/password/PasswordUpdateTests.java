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
package it.infn.mw.iam.test.api.account.password;

import static it.infn.mw.iam.test.TestUtils.passwordTokenGetter;
import static org.hamcrest.Matchers.containsString;
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
import it.infn.mw.iam.api.account.password_reset.PasswordUpdateController;
import it.infn.mw.iam.api.scim.model.ScimEmail;
import it.infn.mw.iam.api.scim.model.ScimName;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.provisioning.ScimUserProvisioning;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.TestUtils;
import it.infn.mw.iam.test.util.annotation.IamRandomPortIntegrationTest;

@RunWith(SpringRunner.class)
@IamRandomPortIntegrationTest
public class PasswordUpdateTests {

  @Value("${local.server.port}")
  private Integer iamPort;

  private ScimUser testUser;

  private final String USER_USERNAME = "password_tester_user";
  private final String USER_PASSWORD = "password";
  private final ScimName USER_NAME =
      ScimName.builder().givenName("TESTER").familyName("USER").build();
  private final ScimEmail USER_EMAIL =
      ScimEmail.builder().email("password_tester_user@test.org").build();

  @Autowired
  private ScimUserProvisioning userService;
  @Autowired
  private IamAccountRepository accountRepository;

  @BeforeClass
  public static void init() {
    TestUtils.initRestAssured();
  }

  @Before
  public void testSetup() {

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
  public void testTeardown() {

    userService.delete(testUser.getId());
  }

  private ValidatableResponse doPost(String accessToken, String currentPassword,
      String newPassword) {

    return RestAssured.given()
      .port(iamPort)
      .auth()
      .preemptive()
      .oauth2(accessToken)
      .formParam(PasswordUpdateController.CURRENT_PASSWORD, currentPassword)
      .formParam(PasswordUpdateController.UPDATED_PASSWORD, newPassword)
      .log()
      .all(true)
      .when()
      .post(PasswordUpdateController.BASE_URL)
      .then()
      .log()
      .all(true);
  }

  private ValidatableResponse doPost(String currentPassword, String newPassword) {

    return RestAssured.given()
      .port(iamPort)
      .formParam(PasswordUpdateController.CURRENT_PASSWORD, currentPassword)
      .formParam(PasswordUpdateController.UPDATED_PASSWORD, newPassword)
      .log()
      .all(true)
      .when()
      .post(PasswordUpdateController.BASE_URL)
      .then()
      .log()
      .all(true);
  }

  @Test
  public void testUpdatePassword() {

    String currentPassword = "password";
    String newPassword = "secure_password";


    String accessToken = passwordTokenGetter().port(iamPort)
      .username(testUser.getUserName())
      .password(currentPassword)
      .getAccessToken();

    doPost(accessToken, currentPassword, newPassword).statusCode(HttpStatus.OK.value());

    passwordTokenGetter().port(iamPort)
      .username(testUser.getUserName())
      .password(newPassword)
      .getAccessToken();
  }

  @Test
  public void testUpdatePasswordFullAuthenticationRequired() {

    String currentPassword = "password";
    String newPassword = "secure_password";

    doPost(currentPassword, newPassword).statusCode(HttpStatus.UNAUTHORIZED.value())
      .body("error", equalTo("unauthorized"))
      .body("error_description",
          equalTo("Full authentication is required to access this resource"));
  }

  @Test
  public void testUpdateWrongPasswordProvided() {

    String currentPassword = "password";
    String newPassword = "secure_password";
    String accessToken = passwordTokenGetter().port(iamPort)
      .username(testUser.getUserName())
      .password(currentPassword)
      .getAccessToken();

    doPost(accessToken, "thisisnotthecurrentpassword", newPassword)
      .statusCode(HttpStatus.BAD_REQUEST.value())
      .body(equalTo("Wrong password provided"));
  }

  @Test
  public void testUpdatePasswordForbiddenAccess() {

    String currentPassword = "password";
    String newPassword = "secure_password";
    String accessToken = TestUtils.clientCredentialsTokenGetter().port(iamPort).getAccessToken();

    doPost(accessToken, currentPassword, newPassword).statusCode(HttpStatus.FORBIDDEN.value());
  }

  @Test
  public void testUpdatePasswordNullPasswordAccess() {

    String currentPassword = "password";
    String newPassword = null;
    String accessToken = passwordTokenGetter().port(iamPort)
      .username(testUser.getUserName())
      .password(currentPassword)
      .getAccessToken();

    doPost(accessToken, currentPassword, newPassword).statusCode(HttpStatus.BAD_REQUEST.value())
      .body(containsString("The password cannot be empty"));
  }

  @Test
  public void testUpdatePasswordEmptyPasswordAccess() {

    String currentPassword = "password";
    String newPassword = "";
    String accessToken = passwordTokenGetter().port(iamPort)
      .username(testUser.getUserName())
      .password(currentPassword)
      .getAccessToken();

    doPost(accessToken, currentPassword, newPassword).statusCode(HttpStatus.BAD_REQUEST.value())
      .body(containsString("The password cannot be empty"));
  }

  @Test
  public void testUpdatePasswordTooShortPasswordAccess() {

    String currentPassword = "password";
    String newPassword = "pass";
    String accessToken = passwordTokenGetter().port(iamPort)
      .username(testUser.getUserName())
      .password(currentPassword)
      .getAccessToken();

    doPost(accessToken, currentPassword, newPassword).statusCode(HttpStatus.BAD_REQUEST.value())
      .body(containsString("The password must be at least 5 characters"));
  }

  @Test
  public void testUpdatePasswordUserNotActive() throws Exception {

    String currentPassword = "password";
    String newPassword = "newPassword";
    String accessToken = passwordTokenGetter().port(iamPort)
      .username(testUser.getUserName())
      .password(currentPassword)
      .getAccessToken();

    IamAccount account = accountRepository.findByUsername(testUser.getUserName())
      .orElseThrow(() -> new Exception("Test user not found"));
    account.setActive(false);
    accountRepository.save(account);

    doPost(accessToken, currentPassword, newPassword).statusCode(HttpStatus.CONFLICT.value())
      .body(containsString("Account is not active or email is not verified"));
  }
}
