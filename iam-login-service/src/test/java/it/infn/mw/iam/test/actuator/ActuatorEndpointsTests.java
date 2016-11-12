package it.infn.mw.iam.test.actuator;

import java.util.Set;

import org.hamcrest.Matchers;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.google.common.collect.Sets;
import com.jayway.restassured.RestAssured;

import it.infn.mw.iam.IamLoginService;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = IamLoginService.class)
@WebIntegrationTest
public class ActuatorEndpointsTests {

  @Value("${server.port}")
  private Integer iamPort;

  private static final String ADMIN_USERNAME = "admin";
  private static final String ADMIN_PASSWORD = "password";

  private static final String USER_USERNAME = "test";
  private static final String USER_PASSWORD = "password";

  private static final Set<String> SENSITIVE_ENDPOINTS = Sets.newHashSet("/metrics", "/configprops",
      "/env", "/mappings", "/flyway", "/autoconfig", "/beans", "/dump", "/trace");

  @Test
  public void testHealthEndpoint() {
    // @formatter:off
    RestAssured.given()
      .port(iamPort)
    .when()
      .get("/health")
    .then()
      .log()
        .body(true)
      .statusCode(HttpStatus.OK.value())
      .body("status", Matchers.equalTo("UP"))
    ;
    // @formatter:on
  }

  @Test
  public void testHealthEndpointAsUser() {
    // @formatter:off
    RestAssured.given()
      .port(iamPort)
      .auth()
        .preemptive()
          .basic(USER_USERNAME, USER_PASSWORD)
    .when()
      .get("/health")
    .then()
      .log()
        .body(true)
      .statusCode(HttpStatus.OK.value())
      .body("status", Matchers.equalTo("UP"))
      .body("diskSpace", Matchers.isEmptyOrNullString())
      .body("db", Matchers.isEmptyOrNullString())
    ;
    // @formatter:on
  }

  @Test
  public void testHealthEndpointAsAdmin() {
    // @formatter:off
    RestAssured.given()
      .port(iamPort)
      .auth()
        .preemptive()
          .basic(ADMIN_USERNAME, ADMIN_PASSWORD)
    .when()
      .get("/health")
    .then()
      .log()
        .body(true)
      .statusCode(HttpStatus.OK.value())
      .body("status", Matchers.equalTo("UP"))
      .body("diskSpace.status", Matchers.equalTo("UP"))
      .body("db.status", Matchers.equalTo("UP"))
    ;
    // @formatter:on
  }

  @Test
  public void testInfoEndpoint() {
    // @formatter:off
    RestAssured.given()
      .port(iamPort)
    .when()
      .get("/info")
    .then()
      .log()
        .body(true)
      .statusCode(HttpStatus.OK.value())
      .body("git", Matchers.notNullValue())
      .body("app", Matchers.notNullValue())
      .body("app.name", Matchers.equalTo("IAM Login Service"))
    ;
    // @formatter:on
  }

  @Test
  public void testInfoEndpointAsUser() {
    // @formatter:off
    RestAssured.given()
      .port(iamPort)
      .auth()
        .preemptive()
          .basic(USER_USERNAME, USER_PASSWORD)
    .when()
      .get("/info")
    .then()
      .log()
        .body(true)
      .statusCode(HttpStatus.OK.value())
      .body("git", Matchers.notNullValue())
      .body("app", Matchers.notNullValue())
      .body("app.name", Matchers.equalTo("IAM Login Service"))
    ;
    // @formatter:on
  }

  @Test
  public void testInfoEndpointAsAdmin() {
    // @formatter:off
    RestAssured.given()
      .port(iamPort)
      .auth()
        .preemptive()
          .basic(ADMIN_USERNAME, ADMIN_PASSWORD)
    .when()
      .get("/info")
    .then()
      .log()
        .body(true)
      .statusCode(HttpStatus.OK.value())
      .body("git", Matchers.notNullValue())
      .body("app", Matchers.notNullValue())
      .body("app.name", Matchers.equalTo("IAM Login Service"))
    ;
    // @formatter:on
  }

  @Test
  public void testSensitiveEndpointsAsAnonymous() {
    for (String endpoint : SENSITIVE_ENDPOINTS) {
      // @formatter:off
	  RestAssured.given()
	    .port(iamPort)
	  .when()
	    .get(endpoint)
	  .then()
	    .log()
	      .body(true)
	    .statusCode(HttpStatus.UNAUTHORIZED.value())
	  ;
	  // @formatter:on
    }
  }

  @Test
  public void testSensitiveEndpointAsUser() {
    for (String endpoint : SENSITIVE_ENDPOINTS) {
      // @formatter:off
	  RestAssured.given()
	    .port(iamPort)
	    .auth()
	      .preemptive()
	        .basic(USER_USERNAME, USER_PASSWORD)
	  .when()
	    .get(endpoint)
	  .then()
	    .log()
	      .body(true)
	    .statusCode(HttpStatus.FORBIDDEN.value())
	  ;
	  // @formatter:on
    }
  }

  @Test
  public void testSensitiveEndpointAsAdmin() {
    for (String endpoint : SENSITIVE_ENDPOINTS) {
      // @formatter:off
	  RestAssured.given()
	    .port(iamPort)
	    .auth()
	      .preemptive()
	        .basic(ADMIN_USERNAME, ADMIN_PASSWORD)
	  .when()
	    .get(endpoint)
	  .then()
	    .log()
	      .body(true)
	    .statusCode(HttpStatus.OK.value())
	  ;
	  // @formatter:on
    }
  }

}
