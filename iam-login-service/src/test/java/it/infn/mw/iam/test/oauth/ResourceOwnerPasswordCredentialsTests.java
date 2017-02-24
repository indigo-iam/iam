package it.infn.mw.iam.test.oauth;

import static com.jayway.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertNotNull;

import java.text.ParseException;

import javax.transaction.Transactional;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.IamLoginService;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = IamLoginService.class)
@WebIntegrationTest
@Transactional
public class ResourceOwnerPasswordCredentialsTests {

  @Test
  public void testDiscoveryEndpoint() {

    // @formatter:off
    given().port(8080).when().get("/.well-known/openid-configuration").then().body("issuer",
        equalTo("http://localhost:8080/"));
    // @formatter:on
  }

  @Test
  public void testResourceOwnerPasswordCredentialsFlow() {

    String clientId = "password-grant";
    String clientSecret = "secret";

    // @formatter:off
    given().auth().preemptive().basic(clientId, clientSecret).port(8080)
        .param("grant_type", "password").param("username", "test").param("password", "password")
        .param("scope", "openid profile").expect().log().body(true).statusCode(200)
        .body("scope", equalTo("openid profile")).when().post("/token");
    // @formatter:on
  }

  @Test
  public void testInvalidResourceOwnerPasswordCredentials() {

    String clientId = "password-grant";
    String clientSecret = "secret";

    // @formatter:off
    given().auth().preemptive().basic(clientId, clientSecret).port(8080)
        .param("grant_type", "password").param("username", "test")
        .param("password", "wrong_password").param("scope", "openid profile").expect().log()
        .body(true).statusCode(400).body("error", equalTo("invalid_grant"))
        .body("error_description", equalTo("Bad credentials")).when().post("/token");
    // @formatter:on

  }

  @Test
  public void testResourceOwnerPasswordCredentialsInvalidClientCredentials() {

    String clientId = "password-grant";
    String clientSecret = "socret";

    // @formatter:off
    given().auth().preemptive().basic(clientId, clientSecret).port(8080)
        .param("grant_type", "password").param("username", "test").param("password", "password")
        .param("scope", "openid profile").expect().log().body(true).statusCode(401)
        .body("error", equalTo("Unauthorized")).body("message", equalTo("Bad credentials")).when()
        .post("/token");
    // @formatter:on

  }

  @Test
  public void testResourceOwnerPasswordCredentialsUnknownClient() {

    String clientId = "unknown";
    String clientSecret = "socret";

    // @formatter:off
    given().auth().preemptive().basic(clientId, clientSecret).port(8080)
        .param("grant_type", "password").param("username", "test").param("password", "password")
        .param("scope", "openid profile").expect().log().body(true).statusCode(401)
        .body("error", equalTo("Unauthorized"))
        .body("message", equalTo("Client with id unknown was not found")).when().post("/token");
    // @formatter:on

  }

  @Test
  public void testResourceOwnerPasswordCredentialAuthenticationTimestamp() throws ParseException {

    String clientId = "password-grant";
    String clientSecret = "secret";

    String idToken = given().auth()
      .preemptive()
      .basic(clientId, clientSecret)
      .port(8080)
      .param("grant_type", "password")
      .param("username", "test")
      .param("password", "password")
      .param("scope", "openid profile")
      .when()
      .post("/token")
      .then()
      .log()
      .body(true)
      .statusCode(200)
      .extract()
      .path("id_token");

    JWT token = JWTParser.parse(idToken);
    System.out.println(token.getJWTClaimsSet());
    assertNotNull(token.getJWTClaimsSet().getClaim("auth_time"));

  }
}
