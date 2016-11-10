package it.infn.mw.iam.test.account;

import static it.infn.mw.iam.test.TestUtils.passwordTokenGetter;

import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.jayway.restassured.RestAssured;
import com.jayway.restassured.response.ValidatableResponse;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.account.PasswordUpdateController;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.provisioning.ScimUserProvisioning;
import it.infn.mw.iam.test.TestUtils;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = IamLoginService.class)
@WebIntegrationTest
public class PasswordUpdateTests {

  @Value("${server.port}")
  private Integer iamPort;

  private ScimUser testUser;

  @Autowired
  private ScimUserProvisioning userService;

  @BeforeClass
  public static void init() {
    TestUtils.initRestAssured();
  }

  @Before
  public void testSetup() {

    testUser = createTestUser("johnLennon", "password", "John", "Lennon", "jl@liverpool.uk");
  }

  @After
  public void testTeardown() {

    deleteTestUser();
  }

  @Test
  public void testUpdatePassword() {

    String currentPassword = "password";
    String newPassword = "secure_password";


    String accessToken = passwordTokenGetter().username(testUser.getUserName())
      .password(currentPassword)
      .getAccessToken();

    doPost(accessToken, currentPassword, newPassword).statusCode(HttpStatus.OK.value());

    passwordTokenGetter().username(testUser.getUserName()).password(newPassword).getAccessToken();
  }

  @Test
  public void testUpdatePasswordFullAuthenticationRequired() {

    String currentPassword = "password";
    String newPassword = "secure_password";

    doPost(currentPassword, newPassword).statusCode(HttpStatus.UNAUTHORIZED.value())
      .body("error", Matchers.equalTo("unauthorized"))
      .body("error_description",
          Matchers.equalTo("Full authentication is required to access this resource"));
  }

  @Test
  public void testUpdateWrongPasswordProvided() {

    String currentPassword = "password";
    String newPassword = "secure_password";
    String accessToken = passwordTokenGetter().username(testUser.getUserName())
      .password(currentPassword)
      .getAccessToken();

    doPost(accessToken, "thisisnotthecurrentpassword", newPassword)
      .statusCode(HttpStatus.BAD_REQUEST.value()).body(Matchers.equalTo("Wrong password provided"));
  }

  @Test
  public void testUpdatePasswordForbiddenAccess() {

    String currentPassword = "password";
    String newPassword = "secure_password";
    String accessToken = TestUtils.clientCredentialsTokenGetter().getAccessToken();

    doPost(accessToken, currentPassword, newPassword).statusCode(HttpStatus.FORBIDDEN.value());
  }

  @Test
  public void testUpdatePasswordNullPasswordAccess() {

    String currentPassword = "password";
    String newPassword = null;
    String accessToken = passwordTokenGetter().username(testUser.getUserName())
      .password(currentPassword)
      .getAccessToken();

    doPost(accessToken, currentPassword, newPassword).statusCode(HttpStatus.BAD_REQUEST.value())
      .body(Matchers.containsString("The password cannot be empty"));
  }

  @Test
  public void testUpdatePasswordEmptyPasswordAccess() {

    String currentPassword = "password";
    String newPassword = "";
    String accessToken = passwordTokenGetter().username(testUser.getUserName())
      .password(currentPassword)
      .getAccessToken();

    doPost(accessToken, currentPassword, newPassword).statusCode(HttpStatus.BAD_REQUEST.value())
      .body(Matchers.containsString("The password cannot be empty"));
  }

  @Test
  public void testUpdatePasswordTooShortPasswordAccess() {

    String currentPassword = "password";
    String newPassword = "pass";
    String accessToken = passwordTokenGetter().username(testUser.getUserName())
      .password(currentPassword)
      .getAccessToken();

    doPost(accessToken, currentPassword, newPassword).statusCode(HttpStatus.BAD_REQUEST.value())
      .body(Matchers.containsString("The password must be at least 5 characters"));
  }

  private ScimUser createTestUser(final String username, final String password,
      final String givenname, final String familyname, final String email) {

    return userService.create(ScimUser.builder()
      .active(true)
      .buildEmail(email)
      .buildName(givenname, familyname)
      .displayName(username)
      .userName(username)
      .password(password)
      .build());
  }

  private void deleteTestUser() {

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
}
