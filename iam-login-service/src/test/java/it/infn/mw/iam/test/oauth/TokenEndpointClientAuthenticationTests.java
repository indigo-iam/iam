package it.infn.mw.iam.test.oauth;

import static com.jayway.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

import javax.transaction.Transactional;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import it.infn.mw.iam.IamLoginService;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = IamLoginService.class)
@WebIntegrationTest
@Transactional
public class TokenEndpointClientAuthenticationTests {

  @Test
  public void testTokenEndpointFormClientAuthentication() {

    String clientId = "post-client";
    String clientSecret = "secret";

    // @formatter:off
    given().port(8080).param("grant_type", "client_credentials").param("client_id", clientId)
        .param("client_secret", clientSecret).param("scope", "read-tasks").expect().log().body(true)
        .statusCode(200).body("scope", equalTo("read-tasks")).when().post("/token");
    // @formatter:on
  }

  @Test
  public void testTokenEndpointFormClientAuthenticationInvalidCredentials() {

    String clientId = "post-client";
    String clientSecret = "wrong-password";

    // @formatter:off
    given().port(8080).param("grant_type", "client_credentials").param("client_id", clientId)
        .param("client_secret", clientSecret).param("scope", "read-tasks").expect().log().body(true)
        .statusCode(401).body("error", equalTo("invalid_client"))
        .body("error_description", equalTo("Bad client credentials")).when().post("/token");
    // @formatter:on
  }

  @Test
  public void testTokenEndpointFormClientAuthenticationUnknownClient() {

    String clientId = "unknown-client";
    String clientSecret = "password";

    // @formatter:off
    given().port(8080).param("grant_type", "client_credentials").param("client_id", clientId)
        .param("client_secret", clientSecret).param("scope", "read-tasks").expect().log().body(true)
        .statusCode(401).body("error", equalTo("invalid_client"))
        .body("error_description", equalTo("Client with id unknown-client was not found")).when()
        .post("/token");
    // @formatter:on
  }

  @Test
  public void testTokenEndpointBasicClientAuthentication() {

    String clientId = "post-client";
    String clientSecret = "secret";

    // @formatter:off
    given().auth().preemptive().basic(clientId, clientSecret).port(8080)
        .param("grant_type", "client_credentials").param("scope", "read-tasks").expect().log()
        .body(true).statusCode(200).body("scope", equalTo("read-tasks")).when().post("/token");
    // @formatter:on
  }

}
