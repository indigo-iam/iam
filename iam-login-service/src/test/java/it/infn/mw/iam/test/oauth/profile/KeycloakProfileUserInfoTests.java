package it.infn.mw.iam.test.oauth.profile;

import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.Matchers.nullValue;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import io.restassured.RestAssured;
import it.infn.mw.iam.test.TestUtils;
import it.infn.mw.iam.test.util.annotation.IamRandomPortIntegrationTest;

@RunWith(SpringRunner.class)
@IamRandomPortIntegrationTest
@TestPropertySource(properties = {
// @formatter:off
    "iam.jwt-profile.default-profile=kc",
    // @formatter:on
})
public class KeycloakProfileUserInfoTests {
  
  @Value("${local.server.port}")
  private Integer iamPort;

  private static final String USERNAME = "test";
  private static final String PASSWORD = "password";
  
  private String userinfoUrl;
  private static final String USERINFO_URL_TEMPLATE = "http://localhost:%d/userinfo";
  
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
      .scope("openid profile")
      .getAccessToken();

    RestAssured.given()
      .header("Authorization", String.format("Bearer %s", accessToken))
      .when()
      .get(userinfoUrl)
      .then()
      .statusCode(HttpStatus.OK.value())
      .body("\"roles\"", hasItems("Analysis", "Production"));
  }
  
  @Test
  public void testUserinfoResponseWithoutGroups() {
    String accessToken = TestUtils.passwordTokenGetter()
      .port(iamPort)
      .username(USERNAME)
      .password(PASSWORD)
      .scope("openid")
      .getAccessToken();

    RestAssured.given()
      .header("Authorization", String.format("Bearer %s", accessToken))
      .when()
      .get(userinfoUrl)
      .then()
      .statusCode(HttpStatus.OK.value())
      .body("\"roles\"", nullValue());
  }
}
