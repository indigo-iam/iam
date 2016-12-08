package it.infn.mw.iam.test.oauth;



import static com.jayway.restassured.RestAssured.given;
import static it.infn.mw.iam.test.TestUtils.passwordTokenGetter;
import static org.hamcrest.Matchers.equalTo;

import javax.transaction.Transactional;

import org.hamcrest.Matchers;
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
@Transactional
public class IntrospectionEndpointTests {

  @Test
  public void testIntrospectionEndpointRetursBasicUserInformation() {
    String accessToken =
        passwordTokenGetter().username("test").password("password").getAccessToken();

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
      .body("active", equalTo(true))
      .body("groups", Matchers.hasSize(Matchers.equalTo(2)))
      .body("groups", Matchers.containsInAnyOrder("Production", "Analysis"))
      .body("preferred_username", Matchers.equalTo("test"))
      .body("organisation_name", Matchers.equalTo("indigo-dc"))
      .body("email", Matchers.equalTo("test@iam.test"));
    // @formatter:on
  }

  @Test
  public void testNoGroupsReturnedWithoutProfileScope() {
    String accessToken = passwordTokenGetter().username("test")
      .password("password")
      .scope("openid")
      .getAccessToken();

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
      .body("active", equalTo(true))
      .body("groups", Matchers.nullValue())
      .body("preferred_username", Matchers.nullValue())
      .body("organisation_name", Matchers.nullValue())
      .body("email", Matchers.nullValue());
    // @formatter:on
  }

  @Test
  public void testEmailReturnedWithEmailScope() {
    String accessToken = passwordTokenGetter().username("test")
      .password("password")
      .scope("openid email")
      .getAccessToken();

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
      .body("active", equalTo(true))
      .body("groups", Matchers.nullValue())
      .body("preferred_username", Matchers.nullValue())
      .body("organisation_name", Matchers.nullValue())
      .body("email", Matchers.equalTo("test@iam.test"));
    // @formatter:on
  }

}
