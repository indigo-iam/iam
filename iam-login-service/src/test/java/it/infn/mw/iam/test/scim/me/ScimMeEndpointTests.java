package it.infn.mw.iam.test.scim.me;

import static com.jayway.restassured.RestAssured.given;
import static it.infn.mw.iam.api.scim.model.ScimConstants.SCIM_CONTENT_TYPE;
import static it.infn.mw.iam.test.TestUtils.clientCredentialsTokenGetter;
import static it.infn.mw.iam.test.TestUtils.passwordTokenGetter;
import static org.hamcrest.Matchers.equalTo;

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
public class ScimMeEndpointTests {


  @Test
  public void meEndpointUserInfo() {

    String accessToken =
        passwordTokenGetter().username("test").password("password").getAccessToken();

    given().port(8080)
      .auth()
      .preemptive()
      .oauth2(accessToken)
      .accept(SCIM_CONTENT_TYPE)
      .log()
      .all(true)
      .when()
      .get("/scim/Me")
      .then()
      .log()
      .all(true)
      .statusCode(HttpStatus.OK.value());

  }

  @Test
  public void meEndpointFailsForClientWithoutUser() {

    String accessToken = clientCredentialsTokenGetter("registration-client", "secret").getAccessToken();
    // TBD: the test that fails with

    given().port(8080)
      .auth()
      .preemptive()
      .oauth2(accessToken)
      .accept(SCIM_CONTENT_TYPE)
      .log()
      .all(true)
      .when()
      .get("/scim/Me")
      .then()
      .log()
      .all(true)
      .statusCode(HttpStatus.BAD_REQUEST.value())
      .body("status", equalTo("400"))
      .body("detail", equalTo("No user linked to the current OAuth token"));
  }

}
