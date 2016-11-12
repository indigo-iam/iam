package it.infn.mw.iam.test.registration;

import static com.jayway.restassured.RestAssured.given;
import static it.infn.mw.iam.api.scim.model.ScimConstants.SCIM_CONTENT_TYPE;
import static it.infn.mw.iam.test.RegistrationUtils.confirmRegistrationRequest;
import static it.infn.mw.iam.test.RegistrationUtils.createRegistrationRequest;
import static it.infn.mw.iam.test.RegistrationUtils.deleteUser;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

import org.hamcrest.Matchers;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.core.IamRegistrationRequestStatus;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.registration.PersistentUUIDTokenGenerator;
import it.infn.mw.iam.registration.RegistrationRequestDto;
import it.infn.mw.iam.test.RegistrationUtils;
import it.infn.mw.iam.test.TestUtils;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = IamLoginService.class)
@WebIntegrationTest
public class RegistrationTests {

  @Autowired
  private PersistentUUIDTokenGenerator generator;

  @Value("${server.port}")
  private Integer iamPort;

  @Autowired
  private IamAccountRepository accountRepository;

  @BeforeClass
  public static void init() {

    TestUtils.initRestAssured();
  }

  @Test
  public void testCreateRequest() {

    RegistrationRequestDto reg = createRegistrationRequest("test_create");

    assertNotNull(reg);
    assertThat(reg.getUsername(), equalTo("test_create"));
    assertThat(reg.getGivenname(), equalTo("Test"));
    assertThat(reg.getFamilyname(), equalTo("User"));
    assertThat(reg.getEmail(), equalTo("test_create@example.org"));
    assertThat(reg.getNotes(), equalTo("Some short notes..."));

    deleteUser(reg.getAccountId());
  }

  @Test
  public void testListNewRequests() {

    String accessToken =
        TestUtils.getAccessToken("registration-client", "secret", "registration:read");

    RegistrationRequestDto reg = createRegistrationRequest("test_list_new");

    // @formatter:off
    given()
      .port(iamPort)
      .auth()
        .preemptive()
        .oauth2(accessToken)
      .param("status", IamRegistrationRequestStatus.NEW)
    .when()
      .get("/registration/list")
    .then()
      .log()
        .body(true)
      .statusCode(HttpStatus.OK.value())
      .body("size()", Matchers.greaterThanOrEqualTo(1));
    // @formatter:on

    deleteUser(reg.getAccountId());
  }

  @Test
  public void testListPendingRequest() {
    String accessToken =
        TestUtils.getAccessToken("registration-client", "secret", "registration:read");

    RegistrationRequestDto reg1 = createRegistrationRequest("test_1");

    RegistrationRequestDto reg2 = createRegistrationRequest("test_2");
    String confirmationKey = generator.getLastToken();
    RegistrationUtils.confirmRegistrationRequest(confirmationKey);

    RegistrationRequestDto reg3 = createRegistrationRequest("test_3");
    RegistrationUtils.approveRequest(reg3.getUuid());

    // @formatter:off
    // 1 NEW, 1 CONFIRMED, 1 APPROVED -> expect 2 elements returned
    given()
      .port(iamPort)
      .auth()
        .preemptive()
        .oauth2(accessToken)
    .when()
      .get("/registration/list/pending")
    .then()
      .log()
        .body(true)
      .statusCode(HttpStatus.OK.value())
      .body("size()", Matchers.greaterThanOrEqualTo(2));
    // @formatter:on

    deleteUser(reg1.getAccountId());
    deleteUser(reg2.getAccountId());
    deleteUser(reg3.getAccountId());
  }

  @Test
  public void testListRequestsUnauthorized() {

    // @formatter:off
    given()
      .port(iamPort)
      .param("status", IamRegistrationRequestStatus.NEW)
    .when()
      .get("/registration/list")
    .then()
      .log()
        .body(true)
      .statusCode(HttpStatus.UNAUTHORIZED.value());
    // @formatter:on
  }

  @Test
  public void testListAllRequests() {

    String accessToken =
        TestUtils.getAccessToken("registration-client", "secret", "registration:read");

    RegistrationRequestDto reg1 = createRegistrationRequest("test_list_1");
    RegistrationRequestDto reg2 = createRegistrationRequest("test_list_2");

    String token = generator.getLastToken();
    assertNotNull(token);

    confirmRegistrationRequest(token);

    // @formatter:off
    given()
      .port(iamPort)
      .auth()
        .preemptive()
        .oauth2(accessToken)
    .when()
      .get("/registration/list")
    .then()
      .log()
        .body(true)
      .statusCode(HttpStatus.OK.value())
      .body("size()", Matchers.greaterThanOrEqualTo(2));
    // @formatter:on

    deleteUser(reg1.getAccountId());
    deleteUser(reg2.getAccountId());
  }

  @Test
  public void testConfirmRequest() {

    RegistrationRequestDto reg = createRegistrationRequest("test_confirm");

    String token = generator.getLastToken();

    assertNotNull(token);

    confirmRegistrationRequest(token);

    deleteUser(reg.getAccountId());
  }

  @Test
  public void testConfirmRequestFailureWithWrongToken() {

    RegistrationRequestDto reg = createRegistrationRequest("test_confirm_fail");

    String badToken = "abcdefghilmnopqrstuvz";

    // @formatter:off
    given()
      .port(iamPort)
      .pathParam("token", badToken)
    .when()
      .get("/registration/confirm/{token}")
    .then()
      .log()
        .body(true)
      .statusCode(HttpStatus.NOT_FOUND.value());
    // @formatter:on

    deleteUser(reg.getAccountId());
  }

  @Test
  public void testApproveRequest() {

    String accessToken =
        TestUtils.getAccessToken("registration-client", "secret", "registration:write");

    // create new request
    RegistrationRequestDto reg = createRegistrationRequest("test_approve");
    assertNotNull(reg);

    String token = generator.getLastToken();
    assertNotNull(token);

    // confirm
    confirmRegistrationRequest(token);

    // approve it
    // @formatter:off
    given()
      .port(iamPort)
      .auth()
        .preemptive()
        .oauth2(accessToken)
      .pathParam("uuid", reg.getUuid())
      .pathParam("decision", IamRegistrationRequestStatus.APPROVED.name())
    .when()
      .post("/registration/{uuid}/{decision}")
    .then()
      .log()
        .body(true)
      .statusCode(HttpStatus.OK.value())
      .body("status", Matchers.equalTo(IamRegistrationRequestStatus.APPROVED.name()))
      .body("uuid", Matchers.equalTo(reg.getUuid()));
    // @formatter:on

    deleteUser(reg.getAccountId());
  }

  @Test
  public void testRejectRequest() {

    String accessToken =
        TestUtils.getAccessToken("registration-client", "secret", "registration:write");

    // create new request
    RegistrationRequestDto reg = createRegistrationRequest("test_reject");
    assertNotNull(reg);

    String token = generator.getLastToken();
    assertNotNull(token);

    // confirm
    confirmRegistrationRequest(token);

    // @formatter:off
    // reject it
    given()
      .port(iamPort)
        .auth()
          .preemptive()
          .oauth2(accessToken)
      .pathParam("uuid", reg.getUuid())
      .pathParam("decision", IamRegistrationRequestStatus.REJECTED.name())
    .when()
      .post("/registration/{uuid}/{decision}")
    .then()
      .log()
        .body(true)
      .statusCode(HttpStatus.OK.value())
      .body("status", Matchers.equalTo(IamRegistrationRequestStatus.REJECTED.name()))
      .body("uuid", Matchers.equalTo(reg.getUuid()));
    // @formatter:on

    // Reject delete user: verify user not found
    accessToken = TestUtils.getAccessToken("registration-client", "secret", "scim:read");

    // @formatter:off
    given()
      .port(iamPort)
        .auth()
          .preemptive()
          .oauth2(accessToken)
      .contentType(SCIM_CONTENT_TYPE)
      .pathParam("uuid", reg.getAccountId())
    .when()
      .get("scim/Users/{uuid}")
    .then()
      .statusCode(HttpStatus.NOT_FOUND.value())
      .body("status", Matchers.equalTo("404"))
    ;
    // @formatter:on
  }

  @Test
  public void testApproveRequestNotConfirmed() {

    String accessToken =
        TestUtils.getAccessToken("registration-client", "secret", "registration:write");

    // create new request
    RegistrationRequestDto reg = createRegistrationRequest("test_approve_not_confirmed");
    assertNotNull(reg);

    // @formatter:off
    // approve it without confirm
    given()
      .port(iamPort)
      .auth()
        .preemptive()
        .oauth2(accessToken)
      .pathParam("uuid", reg.getUuid())
      .pathParam("decision", IamRegistrationRequestStatus.APPROVED.name())
    .when()
      .post("/registration/{uuid}/{decision}")
    .then()
      .log()
        .body(true)
      .statusCode(HttpStatus.OK.value());
    // @formatter:on

    deleteUser(reg.getAccountId());
  }

  @Test
  public void testApproveRequestUnauthorized() {

    // create new request
    RegistrationRequestDto reg = createRegistrationRequest("test_approve_unauth");
    assertNotNull(reg);

    String token = generator.getLastToken();
    assertNotNull(token);

    // confirm
    confirmRegistrationRequest(token);

    // approve it
    // @formatter:off
    given()
      .port(iamPort)
      .pathParam("uuid", reg.getUuid())
      .pathParam("decision", IamRegistrationRequestStatus.APPROVED.name())
    .when()
      .post("/registration/{uuid}/{decision}")
    .then()
      .log()
        .body(true)
      .statusCode(HttpStatus.UNAUTHORIZED.value());
    // @formatter:on

    deleteUser(reg.getAccountId());
  }

  @Test
  public void testWrongDecisionFailure() {

    String accessToken =
        TestUtils.getAccessToken("registration-client", "secret", "registration:write");

    // create new request
    RegistrationRequestDto reg = createRegistrationRequest("test_wrong_decision");
    assertNotNull(reg);

    String token = generator.getLastToken();
    assertNotNull(token);

    // confirm
    confirmRegistrationRequest(token);

    // approve it
    // @formatter:off
    given()
      .port(iamPort)
      .auth()
        .preemptive()
        .oauth2(accessToken)
      .pathParam("uuid", reg.getUuid())
      .pathParam("decision", "wrong")
    .when()
      .post("/registration/{uuid}/{decision}")
    .then()
      .log()
        .body(true)
      .statusCode(HttpStatus.BAD_REQUEST.value());
    // @formatter:on

    deleteUser(reg.getAccountId());
  }

  @Test
  public void testUsernameAvailable() {
    String username = "tester";
    // @formatter:off
    given()
      .port(iamPort)
      .pathParam("username", username)
    .when()
      .get("registration/username-available/{username}")
    .then()
      .log()
        .body(true)
      .statusCode(HttpStatus.OK.value())
      .body(Matchers.equalTo("true"))
    ;
    // @formatter:on
  }

  @Test
  public void testUsernameAlreadyTaken() {
    String username = "admin";
    // @formatter:off
    given()
      .port(iamPort)
      .pathParam("username", username)
    .when()
      .get("registration/username-available/{username}")
    .then()
      .log()
        .body(true)
      .statusCode(HttpStatus.OK.value())
      .body(Matchers.equalTo("false"))
    ;
    // @formatter:on
  }

  @Test
  public void testConfirmAfterApprovation() {

    // create new request
    RegistrationRequestDto reg = createRegistrationRequest("test_confirm_after_approve");
    assertNotNull(reg);
    String confirmationKey = generator.getLastToken();

    RegistrationUtils.approveRequest(reg.getUuid());

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
      .body("status", Matchers.equalTo(IamRegistrationRequestStatus.APPROVED.name()))
    ;
    // @formatter:on

    deleteUser(reg.getAccountId());
  }

}
