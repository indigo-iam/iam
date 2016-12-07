package it.infn.mw.iam.test.oauth;

import static com.jayway.restassured.RestAssured.given;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.text.ParseException;
import java.util.Arrays;

import javax.transaction.Transactional;

import org.hamcrest.Matchers;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.test.TestUtils;


@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = IamLoginService.class)
@WebIntegrationTest
@Transactional
public class TokenExchangeTests {

  @Value("${server.port}")
  private Integer iamPort;

  private final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";
  private final String TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";

  @Test
  public void testImpersonationFlowWithAudience() {

    String clientId = "token-exchange-subject";
    String clientSecret = "secret";

    String actorClientId = "token-exchange-actor";
    String actorClientSecret = "secret";

    String audClientId = "tasks-app";

    String accessToken = TestUtils.passwordTokenGetter(clientId, clientSecret)
      .scope("openid profile")
      .username("test")
      .password("password")
      .getAccessToken();

    // @formatter:off
    String actorAccessToken = 
      given()
        .auth()
          .preemptive()
            .basic(actorClientId, actorClientSecret)
        .port(iamPort)
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
        .statusCode(HttpStatus.OK.value())
        .body("scope", equalTo("read-tasks"))
        .body("issued_token_type", equalTo(TOKEN_TYPE))
        .body("token_type", equalTo("Bearer"))
        .body("access_token", notNullValue())
        .extract()
          .path("access_token");
    // @formatter:on

    // Check audience is encoded in JWT access token
    try {
      JWT jwtAccessToken = JWTParser.parse(actorAccessToken);
      JWTClaimsSet claims = jwtAccessToken.getJWTClaimsSet();

      assertThat(claims.getAudience(), contains("tasks-app"));
      assertThat(claims.getAudience(), hasSize(1));

    } catch (ParseException e) {
      fail(e.getMessage());
    }

    // Check audience is also returned by the introspection endpoint
    // @formatter:off
    // Introspect token
    given()
      .auth()
        .preemptive()
        .basic(actorClientId, actorClientSecret)
      .port(iamPort)
      .formParam("token", actorAccessToken)
      .when()
        .post("/introspect")
      .then()
        .log().body(true)
        .statusCode(HttpStatus.OK.value())
        .body("aud", equalTo("tasks-app"))
        .body("active", equalTo(true))
        .body("scope", equalTo("read-tasks"))
        .body("user_id", equalTo("test"))
        .body("client_id", equalTo(actorClientId));
    // @formatter:on

    // @formatter:off
    // get user info on token, this fails as we did not 
    // request to openid scope
    given()
      .port(iamPort)
      .authentication()
      .preemptive().oauth2(actorAccessToken)
      .when()
        .post("/userinfo")
      .then()
        .log().body(true)
        .statusCode(HttpStatus.FORBIDDEN.value());
    // @formatter:on



  }

  @Test
  public void testImpersonationFlowWithoutAudience() {

    String clientId = "token-exchange-subject";
    String clientSecret = "secret";

    String actorClientId = "token-exchange-actor";
    String actorClientSecret = "secret";

    String accessToken = TestUtils.passwordTokenGetter(clientId, clientSecret)
      .scope("openid profile")
      .username("test")
      .password("password")
      .getAccessToken();

    // @formatter:off
    String actorAccessToken = 
      given()
        .auth()
          .preemptive()
            .basic(actorClientId, actorClientSecret)
        .port(iamPort)
        .param("grant_type", GRANT_TYPE)
        .param("subject_token", accessToken)
        .param("subject_token_type", TOKEN_TYPE)
        .param("scope", "read-tasks openid profile")
      .when()
        .post("/token")
      .then()
        .log()
          .body(true)
        .statusCode(HttpStatus.OK.value())
        .body("scope", equalTo("read-tasks openid profile"))
        .body("issued_token_type", equalTo(TOKEN_TYPE))
        .body("token_type", equalTo("Bearer"))
        .body("access_token", notNullValue())
        .extract()
          .path("access_token");
    // @formatter:on

    // Check audience is NOT encoded in JWT access token
    try {
      JWT jwtAccessToken = JWTParser.parse(actorAccessToken);
      JWTClaimsSet claims = jwtAccessToken.getJWTClaimsSet();

      assertThat(claims.getAudience(), is(nullValue()));

    } catch (ParseException e) {
      fail(e.getMessage());
    }

    // @formatter:off
    // Introspect token
    given()
      .auth()
        .preemptive()
        .basic(actorClientId, actorClientSecret)
      .port(iamPort)
      .formParam("token", actorAccessToken)
      .when()
        .post("/introspect")
      .then()
        .log().body(true)
        .statusCode(HttpStatus.OK.value())
        .body("active", equalTo(true))
        .body("scope", allOf(
            containsString("read-tasks"),
            containsString("openid"),
            containsString("profile")))
        .body("user_id", equalTo("test"))
        .body("client_id", equalTo(actorClientId))
        .body("aud", is(nullValue()));
    // @formatter:on

    // @formatter:off
    // get user info on token, this fails as we did not 
    // request to openid scope
    given()
      .port(iamPort)
      .authentication()
      .preemptive().oauth2(actorAccessToken)
      .when()
        .post("/userinfo")
      .then()
        .log().body(true)
        .statusCode(HttpStatus.OK.value())
        .body("sub", equalTo("80e5fb8d-b7c8-451a-89ba-346ae278a66f"));
    // @formatter:on
  }

  @Test
  public void testUnauthorizedClient() {

    String clientId = "client-cred";
    String clientSecret = "secret";

    String audClientId = "tasks-app";

    String accessToken = TestUtils.passwordTokenGetter(clientId, clientSecret)
      .scope("openid profile")
      .username("test")
      .password("password")
      .getAccessToken();

    // @formatter:off
    given()
      .auth()
        .preemptive()
          .basic(clientId, clientSecret)
      .port(iamPort)
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
      .statusCode(HttpStatus.UNAUTHORIZED.value())
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

    String accessToken = TestUtils.passwordTokenGetter(clientId, clientSecret)
      .scope("openid profile offline_access")
      .username("test")
      .password("password")
      .getAccessToken();

    // @formatter:off
    // get refresh token
    String refreshToken = 
    given()
      .auth()
        .preemptive()
        .basic(actorClientId, actorClientSecret)
      .port(iamPort)
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
      .statusCode(HttpStatus.OK.value())
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
      .port(iamPort)
      .param("grant_type", "refresh_token")
      .param("refresh_token", refreshToken)
      .param("client_id", actorClientId)
      .param("client_secret", actorClientSecret)
    .when()
      .post("/token")
    .then()
      .log()
        .body(true)
      .statusCode(HttpStatus.OK.value())
      .body("access_token", notNullValue());
    // @formatter:on
  }

  @Test
  public void testRequestRefreshTokenWithoutOfflineAccessScope() {

    String clientId = "token-exchange-subject";
    String clientSecret = "secret";

    String actorClientId = "token-exchange-actor";
    String actorClientSecret = "secret";

    String audClientId = "client";

    String accessToken = TestUtils.passwordTokenGetter(clientId, clientSecret)
      .scope("openid")
      .username("test")
      .password("password")
      .getAccessToken();

    // @formatter:off
    given()
      .auth()
        .preemptive()
        .basic(actorClientId, actorClientSecret)
      .port(iamPort)
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
      .statusCode(HttpStatus.BAD_REQUEST.value())
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

    String subjectToken = TestUtils.passwordTokenGetter(clientId, clientSecret)
      .scope("openid")
      .username("test")
      .password("password")
      .getAccessToken();

    String actorToken = TestUtils.passwordTokenGetter(clientId, clientSecret)
      .scope("openid")
      .username("test")
      .password("password")
      .getAccessToken();

    // @formatter:off
    given()
      .auth()
        .preemptive()
        .basic(actorClientId, actorClientSecret)
      .port(iamPort)
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
      .statusCode(HttpStatus.BAD_REQUEST.value())
      .body("error", equalTo("invalid_request"))
      .body("error_description", Matchers.stringContainsInOrder(Arrays.asList("not supported")));
    // @formatter:on
  }

  @Test
  public void testWithInvalidSubjectToken() {

    String actorClientId = "token-exchange-actor";
    String actorClientSecret = "secret";

    String accessToken = "abcdefghilmnopqrstuvz0123456789";

    // @formatter:off
    given()
      .auth()
        .preemptive()
          .basic(actorClientId, actorClientSecret)
      .port(iamPort)
      .param("grant_type", GRANT_TYPE)
      .param("subject_token", accessToken)
      .param("subject_token_type", TOKEN_TYPE)
      .param("scope", "read-tasks")
    .when()
      .post("/token")
    .then()
      .log()
        .body(true)
      .statusCode(HttpStatus.UNAUTHORIZED.value())
      .body("error", equalTo("invalid_token"))
    ;
    // @formatter:on
  }

  @Test
  public void testTokenExchangeFailureForClientCredentialsClient() {

    String accessToken =
        TestUtils.clientCredentialsTokenGetter().scope("read-tasks write-tasks").getAccessToken();

    String actorClientId = "token-exchange-actor";
    String actorClientSecret = "secret";

    // @formatter:off
    given()
      .auth()
        .preemptive()
          .basic(actorClientId, actorClientSecret)
      .port(iamPort)
      .param("grant_type", GRANT_TYPE)
      .param("subject_token", accessToken)
      .param("subject_token_type", TOKEN_TYPE)
      .param("scope", "read-tasks")
    .when()
      .post("/token")
    .then()
      .log()
        .body(true)
      .statusCode(HttpStatus.BAD_REQUEST.value())
      .body("error", equalTo("invalid_request"))
      .body("error_description", Matchers.stringContainsInOrder(Arrays.asList("No user identity linked to subject token.")));
    // @formatter:on


  }
}
