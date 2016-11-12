package it.infn.mw.iam.test;

import static com.jayway.restassured.RestAssured.given;
import static it.infn.mw.iam.api.scim.model.ScimConstants.SCIM_CONTENT_TYPE;

import org.hamcrest.Matchers;
import org.springframework.http.HttpStatus;

import com.jayway.restassured.RestAssured;
import com.jayway.restassured.http.ContentType;

import it.infn.mw.iam.core.IamRegistrationRequestStatus;
import it.infn.mw.iam.registration.RegistrationRequestDto;

public class RegistrationUtils {

  public static RegistrationRequestDto createRegistrationRequest(String username) {

    String email = username + "@example.org";
    RegistrationRequestDto request = new RegistrationRequestDto();
    request.setGivenname("Test");
    request.setFamilyname("User");
    request.setEmail(email);
    request.setUsername(username);
    request.setNotes("Some short notes...");

    // @formatter:off
    RegistrationRequestDto reg = given()
        .port(8080)
        .contentType(ContentType.JSON)
        .body(request)
          .log()
            .all(true)
        .when()
          .post("/registration/create")
        .then()
          .log()
            .body(true)
          .statusCode(HttpStatus.OK.value())
          .extract()
            .as(RegistrationRequestDto.class)
    ;
    // @formatter:on

    return reg;
  }

  public static void deleteUser(String userId) {

    String accessToken =
        TestUtils.getAccessToken("registration-client", "secret", "scim:write scim:read");

    String location = "/scim/Users/" + userId;
    // @formatter:off
    given()
      .port(8080)
      .auth()
        .preemptive()
        .oauth2(accessToken)
      .contentType(SCIM_CONTENT_TYPE)
    .when()
      .delete(location)
    .then()
      .statusCode(HttpStatus.NO_CONTENT.value());

    given()
      .port(8080)
      .auth()
        .preemptive()
        .oauth2(accessToken)
      .contentType(SCIM_CONTENT_TYPE)
    .when()
      .get(location)
    .then()
      .statusCode(HttpStatus.NOT_FOUND.value())
    ;
    // @formatter:on
  }

  public static void confirmRegistrationRequest(String confirmationKey) {

    // @formatter:off
    given()
      .port(8080)
      .pathParam("token", confirmationKey)
    .when()
      .get("/registration/confirm/{token}")
    .then()
      .log()
        .body(true)
      .statusCode(HttpStatus.OK.value())
      .body("status", Matchers.equalTo(IamRegistrationRequestStatus.CONFIRMED.name()))
    ;
    // @formatter:on
  }

  public static RegistrationRequestDto approveRequest(String uuid) {
    return requestDecision(uuid, IamRegistrationRequestStatus.APPROVED);
  }

  public static RegistrationRequestDto rejectRequest(String uuid) {
    return requestDecision(uuid, IamRegistrationRequestStatus.REJECTED);
  }

  public static void changePassword(String resetKey, String newPassword) {
    // @formatter:off
    RestAssured.given()
      .port(8080)
      .param("token", resetKey)
      .param("password", newPassword)
    .when()
      .post("/iam/password-reset")
    .then()
      .log()
        .body(true)
      .statusCode(HttpStatus.OK.value())
    ;
    // @formatter:on
  }

  private static RegistrationRequestDto requestDecision(String uuid,
      IamRegistrationRequestStatus decision) {
    String accessToken =
        TestUtils.getAccessToken("registration-client", "secret", "registration:write");

    // @formatter:off
    RegistrationRequestDto req =
    given()
      .port(8080)
      .auth()
        .preemptive()
        .oauth2(accessToken)
      .pathParam("uuid", uuid)
      .pathParam("decision", decision)
    .when()
      .post("/registration/{uuid}/{decision}")
    .then()
      .log()
        .body(true)
      .statusCode(HttpStatus.OK.value())
      .extract().as(RegistrationRequestDto.class);
    // @formatter:on

    return req;
  }

}
