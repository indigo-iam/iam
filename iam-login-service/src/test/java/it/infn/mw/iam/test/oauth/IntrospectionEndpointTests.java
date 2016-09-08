package it.infn.mw.iam.test.oauth;

import static com.jayway.restassured.RestAssured.given;
import static it.infn.mw.iam.test.TestUtils.clientCredentialsTokenGetter;
import static org.hamcrest.Matchers.equalTo;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import it.infn.mw.iam.IamLoginService;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = IamLoginService.class)
@WebIntegrationTest
public class IntrospectionEndpointTests {

  private String accessToken;

  @Before
  public void initAccessToken() {
    accessToken = clientCredentialsTokenGetter("client-cred", "secret")
      .scope("openid profile offline_access").getAccessToken();

  }

  @Test
  public void testTokenIntrospectionEndpointBasicAuthentication() {
    // @formatter:off
    given()
      .port(8080)
      .auth()
        .preemptive()
          .basic("password-grant", "secret")
      .formParam("token", accessToken)
    .when()
      .post("/introspect")
    .then()
      .log().body(true)
      .statusCode(HttpStatus.OK.value())
      .body("active", equalTo(true));
    // @formatter:on
  }

  @Test
  public void testTokenIntrospectionEndpointFormAuthentication() {
    // @formatter:off
    given()
      .port(8080)
      .formParam("token", accessToken)
      .formParam("client_id", "client-cred")
      .formParam("client_secret", "secret")
      .log().all(true)
    .when()
      .post("/introspect")
    .then()
      .log().all(true)
      .statusCode(HttpStatus.UNAUTHORIZED.value());
    // @formatter:on
  }

  @Test
  public void testTokenIntrospectionEndpointNoAuthenticationFailure() {
    // @formatter:off
    given()
      .port(8080)
      .formParam("token", accessToken)
    .when()
      .post("/introspect")
    .then()
      .log().body(true)
      .statusCode(HttpStatus.UNAUTHORIZED.value());
   // @formatter:on

  }
}
