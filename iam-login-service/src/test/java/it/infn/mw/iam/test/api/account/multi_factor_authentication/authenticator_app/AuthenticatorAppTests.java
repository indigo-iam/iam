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
package it.infn.mw.iam.test.api.account.multi_factor_authentication.authenticator_app;

import static it.infn.mw.iam.test.TestUtils.passwordTokenGetter;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.junit4.SpringRunner;

import dev.samstevens.totp.code.CodeVerifier;
import io.restassured.RestAssured;
import io.restassured.response.ValidatableResponse;
import it.infn.mw.iam.api.account.multi_factor_authentication.authenticator_app.AuthenticatorAppController;
import it.infn.mw.iam.api.scim.model.ScimEmail;
import it.infn.mw.iam.api.scim.model.ScimName;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.provisioning.ScimUserProvisioning;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.TestUtils;
import it.infn.mw.iam.test.util.annotation.IamRandomPortIntegrationTest;

// TODO update these to reflect customisation properties for authenticator app, e.g. code length

@RunWith(SpringRunner.class)
@IamRandomPortIntegrationTest
public class AuthenticatorAppTests {

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
  @Autowired
  private IamAccountRepository accountRepository;

  @MockBean
  private CodeVerifier codeVerifier;

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
    Mockito.reset(codeVerifier);
  }

  private ValidatableResponse doPut(String accessToken) {
    return RestAssured.given()
      .port(iamPort)
      .auth()
      .preemptive()
      .oauth2(accessToken)
      .log()
      .all(true)
      .when()
      .put(AuthenticatorAppController.ADD_SECRET_URL)
      .then()
      .log()
      .all(true);
  }

  private ValidatableResponse doPut() {
    return RestAssured.given()
      .port(iamPort)
      .log()
      .all(true)
      .when()
      .put(AuthenticatorAppController.ADD_SECRET_URL)
      .then()
      .log()
      .all(true);
  }

  private ValidatableResponse doPost(String accessToken, String url, String code) {
    return RestAssured.given()
      .port(iamPort)
      .formParam("code", code)
      .auth()
      .preemptive()
      .oauth2(accessToken)
      .log()
      .all(true)
      .when()
      .post(url)
      .then()
      .log()
      .all(true);
  }

  private ValidatableResponse doPost(String url, String code) {
    return RestAssured.given()
      .port(iamPort)
      .formParam("code", code)
      .log()
      .all(true)
      .when()
      .post(url)
      .then()
      .log()
      .all(true);
  }

  @Test
  public void testAddSecret() {
    String accessToken = passwordTokenGetter().port(iamPort)
      .username(testUser.getUserName())
      .password(USER_PASSWORD)
      .getAccessToken();

    doPut(accessToken).statusCode(HttpStatus.OK.value());
  }

  @Test
  public void testAddSecretFullAuthenticationRequired() {
    doPut().statusCode(HttpStatus.UNAUTHORIZED.value())
      .body("error", equalTo("unauthorized"))
      .body("error_description",
          equalTo("Full authentication is required to access this resource"));
  }

  @Test
  public void testEnableAuthenticatorApp() throws Exception {
    String accessToken = passwordTokenGetter().port(iamPort)
      .username(testUser.getUserName())
      .password(USER_PASSWORD)
      .getAccessToken();

    String code = "123456";

    IamAccount account = accountRepository.findByUsername(testUser.getUserName())
      .orElseThrow(() -> new Exception("Test user not found"));
    IamTotpMfa totpMfa = new IamTotpMfa(account);
    totpMfa.setSecret("test");
    totpMfa.setActive(false);
    account.setTotpMfa(totpMfa);
    accountRepository.save(account);

    when(codeVerifier.isValidCode(anyString(), anyString())).thenReturn(true);

    doPost(accessToken, AuthenticatorAppController.ENABLE_URL, code)
      .statusCode(HttpStatus.OK.value());
  }

  @Test
  public void testEnableAuthenticatorAppIncorrectCode() throws Exception {
    String accessToken = passwordTokenGetter().port(iamPort)
      .username(testUser.getUserName())
      .password(USER_PASSWORD)
      .getAccessToken();

    String code = "123456";

    IamAccount account = accountRepository.findByUsername(testUser.getUserName())
      .orElseThrow(() -> new Exception("Test user not found"));
    IamTotpMfa totpMfa = new IamTotpMfa(account);
    totpMfa.setSecret("test");
    totpMfa.setActive(false);
    account.setTotpMfa(totpMfa);
    accountRepository.save(account);

    when(codeVerifier.isValidCode(anyString(), anyString())).thenReturn(false);

    doPost(accessToken, AuthenticatorAppController.ENABLE_URL, code)
      .statusCode(HttpStatus.BAD_REQUEST.value())
      .body(containsString("Incorrect code"));
  }

  @Test
  public void testEnableAuthenticatorAppInvalidCharactersInCode() throws Exception {
    String accessToken = passwordTokenGetter().port(iamPort)
      .username(testUser.getUserName())
      .password(USER_PASSWORD)
      .getAccessToken();

    String code = "abcdef";

    doPost(accessToken, AuthenticatorAppController.ENABLE_URL, code)
      .statusCode(HttpStatus.BAD_REQUEST.value())
      .body(containsString("Invalid code format"));
  }

  @Test
  public void testEnableAuthenticatorAppCodeTooShort() throws Exception {
    String accessToken = passwordTokenGetter().port(iamPort)
      .username(testUser.getUserName())
      .password(USER_PASSWORD)
      .getAccessToken();

    String code = "12345";

    doPost(accessToken, AuthenticatorAppController.ENABLE_URL, code)
      .statusCode(HttpStatus.BAD_REQUEST.value())
      .body(containsString("Invalid code format"));
  }

  @Test
  public void testEnableAuthenticatorAppCodeTooLong() throws Exception {
    String accessToken = passwordTokenGetter().port(iamPort)
      .username(testUser.getUserName())
      .password(USER_PASSWORD)
      .getAccessToken();

    String code = "1234567";

    doPost(accessToken, AuthenticatorAppController.ENABLE_URL, code)
      .statusCode(HttpStatus.BAD_REQUEST.value())
      .body(containsString("Invalid code format"));
  }

  @Test
  public void testEnableAuthenticatorAppNullCode() throws Exception {
    String accessToken = passwordTokenGetter().port(iamPort)
      .username(testUser.getUserName())
      .password(USER_PASSWORD)
      .getAccessToken();

    String code = null;

    doPost(accessToken, AuthenticatorAppController.ENABLE_URL, code)
      .statusCode(HttpStatus.BAD_REQUEST.value())
      .body(containsString("Invalid code format"));
  }

  @Test
  public void testEnableAuthenticatorAppEmptyCode() throws Exception {
    String accessToken = passwordTokenGetter().port(iamPort)
      .username(testUser.getUserName())
      .password(USER_PASSWORD)
      .getAccessToken();

    String code = "";

    doPost(accessToken, AuthenticatorAppController.ENABLE_URL, code)
      .statusCode(HttpStatus.BAD_REQUEST.value())
      .body(containsString("Invalid code format"));
  }

  @Test
  public void testEnableAuthenticatorAppFullAuthenticationRequired() {
    String code = "123456";

    doPost(AuthenticatorAppController.ENABLE_URL, code).statusCode(HttpStatus.UNAUTHORIZED.value())
      .body("error", equalTo("unauthorized"))
      .body("error_description",
          equalTo("Full authentication is required to access this resource"));
  }

  @Test
  public void testDisableAuthenticatorApp() throws Exception {
    String accessToken = passwordTokenGetter().port(iamPort)
      .username(testUser.getUserName())
      .password(USER_PASSWORD)
      .getAccessToken();

    String code = "123456";

    IamAccount account = accountRepository.findByUsername(testUser.getUserName())
      .orElseThrow(() -> new Exception("Test user not found"));
    IamTotpMfa totpMfa = new IamTotpMfa(account);
    totpMfa.setSecret("test");
    totpMfa.setActive(true);
    account.setTotpMfa(totpMfa);
    accountRepository.save(account);

    when(codeVerifier.isValidCode(anyString(), anyString())).thenReturn(true);

    doPost(accessToken, AuthenticatorAppController.DISABLE_URL, code)
      .statusCode(HttpStatus.OK.value());
  }

  @Test
  public void testDisableAuthenticatorAppIncorrectCode() throws Exception {
    String accessToken = passwordTokenGetter().port(iamPort)
      .username(testUser.getUserName())
      .password(USER_PASSWORD)
      .getAccessToken();

    String code = "123456";

    IamAccount account = accountRepository.findByUsername(testUser.getUserName())
      .orElseThrow(() -> new Exception("Test user not found"));
    IamTotpMfa totpMfa = new IamTotpMfa(account);
    totpMfa.setSecret("test");
    totpMfa.setActive(true);
    account.setTotpMfa(totpMfa);
    accountRepository.save(account);

    when(codeVerifier.isValidCode(anyString(), anyString())).thenReturn(false);

    doPost(accessToken, AuthenticatorAppController.DISABLE_URL, code)
      .statusCode(HttpStatus.BAD_REQUEST.value())
      .body(containsString("Incorrect code"));
  }

  @Test
  public void testDisableAuthenticatorAppInvalidCharactersInCode() throws Exception {
    String accessToken = passwordTokenGetter().port(iamPort)
      .username(testUser.getUserName())
      .password(USER_PASSWORD)
      .getAccessToken();

    String code = "abcdef";

    doPost(accessToken, AuthenticatorAppController.DISABLE_URL, code)
      .statusCode(HttpStatus.BAD_REQUEST.value())
      .body(containsString("Invalid code format"));
  }

  @Test
  public void testDisableAuthenticatorAppCodeTooShort() throws Exception {
    String accessToken = passwordTokenGetter().port(iamPort)
      .username(testUser.getUserName())
      .password(USER_PASSWORD)
      .getAccessToken();

    String code = "12345";

    doPost(accessToken, AuthenticatorAppController.DISABLE_URL, code)
      .statusCode(HttpStatus.BAD_REQUEST.value())
      .body(containsString("Invalid code format"));
  }

  @Test
  public void testDisableAuthenticatorAppCodeTooLong() throws Exception {
    String accessToken = passwordTokenGetter().port(iamPort)
      .username(testUser.getUserName())
      .password(USER_PASSWORD)
      .getAccessToken();

    String code = "1234567";

    doPost(accessToken, AuthenticatorAppController.DISABLE_URL, code)
      .statusCode(HttpStatus.BAD_REQUEST.value())
      .body(containsString("Invalid code format"));
  }

  @Test
  public void testDisableAuthenticatorAppNullCode() throws Exception {
    String accessToken = passwordTokenGetter().port(iamPort)
      .username(testUser.getUserName())
      .password(USER_PASSWORD)
      .getAccessToken();

    String code = null;

    doPost(accessToken, AuthenticatorAppController.DISABLE_URL, code)
      .statusCode(HttpStatus.BAD_REQUEST.value())
      .body(containsString("Invalid code format"));
  }

  @Test
  public void testDisableAuthenticatorAppEmptyCode() throws Exception {
    String accessToken = passwordTokenGetter().port(iamPort)
      .username(testUser.getUserName())
      .password(USER_PASSWORD)
      .getAccessToken();

    String code = "";

    doPost(accessToken, AuthenticatorAppController.DISABLE_URL, code)
      .statusCode(HttpStatus.BAD_REQUEST.value())
      .body(containsString("Invalid code format"));
  }

  @Test
  public void testDisableAuthenticatorAppFullAuthenticationRequired() {
    String code = "123456";

    doPost(AuthenticatorAppController.DISABLE_URL, code).statusCode(HttpStatus.UNAUTHORIZED.value())
      .body("error", equalTo("unauthorized"))
      .body("error_description",
          equalTo("Full authentication is required to access this resource"));
  }
}
