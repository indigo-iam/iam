package it.infn.mw.iam.test.oauth;

import static com.jayway.restassured.RestAssured.given;
import static it.infn.mw.iam.test.TestUtils.clientCredentialsTokenGetter;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;

import java.util.Arrays;

import org.hamcrest.Matchers;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.test.TestUtils;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = IamLoginService.class)
@WebIntegrationTest
public class TokenExchangeTests {

  private final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";
  private final String TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";

  @Test
  public void testImpersonationFlow() {

    String clientId = "token-exchange-subject";
    String clientSecret = "secret";

    String actorClientId = "token-exchange-actor";
    String actorClientSecret = "secret";

    String audClientId = "tasks-app";

    // get access token
    String accessToken = TestUtils.getAccessToken(clientId, clientSecret, "openid profile");

    // @formatter:off
    given()
      .auth()
        .preemptive()
          .basic(actorClientId, actorClientSecret)
      .port(8080)
      .param("grant_type", GRANT_TYPE)
      .param("audience", audClientId)
      .param("subject_token", accessToken)
      .param("subject_token_type", TOKEN_TYPE)
      .param("scope", "read-tasks")
    .when()
      .post("/token")
    .then()
      .log()
        .body(true)
      .statusCode(200)
      .body("scope", equalTo("read-tasks"))
      .body("issued_token_type", equalTo(TOKEN_TYPE))
      .body("token_type", equalTo("Bearer"))
      .body("access_token", notNullValue());
    // @formatter:on
  }

  @Test
  public void testClientWithoutGrantType() {

    String clientId = "client-cred";
    String clientSecret = "secret";

    String audClientId = "tasks-app";

    String accessToken = TestUtils.getAccessToken(clientId, clientSecret, "openid profile");

    // @formatter:off
    given()
      .auth()
        .preemptive()
          .basic(clientId, clientSecret).port(8080)
      .param("grant_type", GRANT_TYPE)
      .param("audience", audClientId)
      .param("subject_token", accessToken)
      .param("subject_token_type", TOKEN_TYPE)
      .param("scope", "read-tasks")
    .when()
      .post("/token")
    .then()
      .log()
        .body(true)
      .statusCode(401)
      .body("error", equalTo("invalid_client"))
      .body("error_description", Matchers.stringContainsInOrder(Arrays.asList("Unauthorized grant type")));
    // @formatter:on
  }

  @Test
  public void testTokenExchangeWithRefreshToken() {

    String clientId = "token-exchange-subject";
    String clientSecret = "secret";

    String actorClientId = "token-exchange-actor";
    String actorClientSecret = "secret";

    String audClientId = "client";

    String accessToken = TestUtils.getAccessToken(clientId, clientSecret, "openid offline_access");

    // @formatter:off
    // get refresh token
    String refreshToken = 
    given()
      .auth()
        .preemptive()
        .basic(actorClientId, actorClientSecret)
      .port(8080)
      .param("grant_type", GRANT_TYPE)
      .param("audience", audClientId)
      .param("subject_token", accessToken)
      .param("subject_token_type", TOKEN_TYPE)
      .param("scope", "openid offline_access read-tasks")
    .when()
      .post("/token")
    .then()
      .log()
        .body(true)
      .statusCode(200)
      .body("scope", equalTo("read-tasks openid offline_access"))
      .body("issued_token_type", equalTo(TOKEN_TYPE))
      .body("token_type", equalTo("Bearer"))
      .body("access_token", notNullValue())
      .body("refresh_token", notNullValue())
      .extract()
        .path("refresh_token");

    // use refresh token
    given()
      .auth()
        .preemptive()
          .basic(actorClientId, actorClientSecret)
      .port(8080)
      .param("grant_type", "refresh_token")
      .param("refresh_token", refreshToken)
      .param("client_id", actorClientId)
      .param("client_secret", actorClientSecret)
    .when()
      .post("/token")
    .then()
      .log()
        .body(true)
      .statusCode(200)
      .body("access_token", notNullValue());
    // @formatter:on
  }

  @Test
  public void testRequestRefreshTokenWithInvalidScope() {

    String clientId = "token-exchange-subject";
    String clientSecret = "secret";

    String actorClientId = "token-exchange-actor";
    String actorClientSecret = "secret";

    String audClientId = "client";

    String accessToken = TestUtils.getAccessToken(clientId, clientSecret, "openid");

    // @formatter:off
    given()
      .auth()
        .preemptive()
        .basic(actorClientId, actorClientSecret)
      .port(8080)
      .param("grant_type", GRANT_TYPE)
      .param("audience", audClientId)
      .param("subject_token", accessToken)
      .param("subject_token_type", TOKEN_TYPE)
      .param("scope", "openid offline_access")
    .when()
      .post("/token")
    .then()
      .log()
        .body(true)
      .statusCode(400)
      .body("error", equalTo("invalid_scope"));
    // @formatter:on
  }

  @Test
  public void testDelegationFlow() {

    String clientId = "token-exchange-subject";
    String clientSecret = "secret";

    String actorClientId = "token-exchange-actor";
    String actorClientSecret = "secret";

    String audClientId = "client";

    String subjectToken =
        clientCredentialsTokenGetter(clientId, clientSecret).scope("openid").getAccessToken();

    String actorToken = clientCredentialsTokenGetter(actorClientId, actorClientSecret)
      .scope("openid").getAccessToken();

    // @formatter:off
    given()
      .auth()
        .preemptive()
        .basic(actorClientId, actorClientSecret)
      .port(8080)
      .param("grant_type", GRANT_TYPE)
      .param("audience", audClientId)
      .param("subject_token", subjectToken)
      .param("subject_token_type", TOKEN_TYPE)
      .param("actor_token", actorToken)
      .param("actor_token_type", TOKEN_TYPE)
      .param("want_composite", "true")
      .param("scope", "read-tasks")
    .when()
      .post("/token")
    .then()
      .log()
        .body(true)
      .statusCode(400)
      .body("error", equalTo("invalid_request"))
      .body("error_description", Matchers.stringContainsInOrder(Arrays.asList("not yet supported")));
    // @formatter:on
  }
}
