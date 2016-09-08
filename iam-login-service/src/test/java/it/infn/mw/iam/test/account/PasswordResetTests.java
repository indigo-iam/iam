package it.infn.mw.iam.test.account;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.jayway.restassured.RestAssured;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.registration.PersistentUUIDTokenGenerator;
import it.infn.mw.iam.registration.RegistrationRequestDto;
import it.infn.mw.iam.test.RegistrationUtils;
import it.infn.mw.iam.test.TestUtils;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = IamLoginService.class)
@WebIntegrationTest
public class PasswordResetTests {

  @Autowired
  private PersistentUUIDTokenGenerator tokenGenerator;

  private RegistrationRequestDto reg;

  @BeforeClass
  public static void init() {
    TestUtils.initRestAssured();
  }

  @Before
  public void setup() {
    String username = "test_user";

    reg = RegistrationUtils.createRegistrationRequest(username);
    String confirmationKey = tokenGenerator.getLastToken();
    RegistrationUtils.confirmRegistrationRequest(confirmationKey);
    RegistrationUtils.approveRequest(reg.getUuid());
  }

  @After
  public void tearDown() {
    RegistrationUtils.deleteUser(reg.getAccountId());
  }



  @Test
  public void testChangePassword() {
    String newPassword = "secure_password";
    String resetKey = tokenGenerator.getLastToken();

    // @formatter:off
    Boolean retval = RestAssured.given()
      .port(8080)
      .pathParam("token", resetKey)
    .when()
      .get("/iam/password/reset-key/{token}")
    .then()
      .log()
        .body(true)
      .statusCode(HttpStatus.OK.value())
      .extract()
        .as(Boolean.class);
    ;
    // @formatter:on
    Assert.assertEquals(Boolean.TRUE, retval);

    // @formatter:off
    RestAssured.given()
      .port(8080)
      .param("resetkey", resetKey)
      .param("password", newPassword)
    .when()
      .post("/iam/password-change")
    .then()
      .log()
        .body(true)
      .statusCode(HttpStatus.OK.value())
    ;
    // @formatter:on
  }

  @Test
  public void testResetPasswordWithInvalidResetKey() {

    String resetKey = "abcdefghilmnopqrstuvz";

    // @formatter:off
    RestAssured.given()
      .port(8080)
      .pathParam("token", resetKey)
    .when()
      .get("/iam/password/reset-key/{token}")
    .then()
      .log()
        .body(true)
      .statusCode(HttpStatus.NOT_FOUND.value())
    ;
    // @formatter:on
  }

  @Test
  public void testForgotPassword() {

    String emailAddress = "test@foo.bar";

    // @formatter:off
    RestAssured.given()
      .port(8080)
      .pathParam("email", emailAddress)
    .when()
      .get("/iam/password-forgot/{email}", emailAddress)
    .then()
      .log()
        .body(true)
      .statusCode(HttpStatus.OK.value())
    ;
    // @formatter:on
  }

  @Test
  public void testReuseSameResetKeyFailure() {
    String newPassword = "secure_password";
    String resetKey = tokenGenerator.getLastToken();

    // @formatter:off
    Object retval = RestAssured.given()
      .port(8080)
      .pathParam("token", resetKey)
    .when()
      .get("/iam/password/reset-key/{token}")
    .then()
      .log()
        .body(true)
      .statusCode(HttpStatus.OK.value())
      .extract()
        .as(Boolean.class)
    ;
    // @formatter:on
    Assert.assertEquals(Boolean.TRUE, retval);

    // update password
    // @formatter:off
    retval = RestAssured.given()
      .port(8080)
      .param("resetkey", resetKey)
      .param("password", newPassword)
    .when()
      .post("/iam/password-change")
    .then()
      .log()
        .body(true)
      .statusCode(HttpStatus.OK.value())
      .extract()
        .asString()
    ;
    
    Assert.assertEquals("ok", retval);
    
    // try re-update with same key
    retval = RestAssured.given()
      .port(8080)
      .param("resetkey", resetKey)
      .param("password", newPassword)
    .when()
      .post("/iam/password-change")
    .then()
      .log()
        .body(true)
      .statusCode(HttpStatus.OK.value())
      .extract()
        .asString()
    ;
    // @formatter:on
    Assert.assertEquals("err", retval);
  }

}
