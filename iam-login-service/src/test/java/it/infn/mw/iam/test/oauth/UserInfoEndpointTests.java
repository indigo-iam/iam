package it.infn.mw.iam.test.oauth;

import static com.jayway.restassured.RestAssured.given;

import javax.transaction.Transactional;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.test.TestUtils;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = IamLoginService.class)
@WebIntegrationTest
@Transactional
public class UserInfoEndpointTests {

  @Test
  public void testUserInfoEndpointReturs404ForClientCredentialsToken() {
    String accessToken = TestUtils.clientCredentialsTokenGetter().scope("openid").getAccessToken();

    // @formatter:off
    given()
      .port(8080)
      .auth().preemptive().oauth2(accessToken)
    .when()
      .get("/userinfo")
    .then()
      .log().all(true)
      .statusCode(HttpStatus.FORBIDDEN.value());
    // @formatter:on
  }

  @Test
  public void testUserInfoEndpointRetursOk() {
    String accessToken = TestUtils.passwordTokenGetter()
      .scope("openid")
      .username("test")
      .password("password")
      .getAccessToken();

    // @formatter:off
    given()
      .port(8080)
      .auth().preemptive().oauth2(accessToken)
    .when()
      .get("/userinfo")
    .then()
      .log().all(true)
      .statusCode(HttpStatus.OK.value());
    // @formatter:on
  }
}
