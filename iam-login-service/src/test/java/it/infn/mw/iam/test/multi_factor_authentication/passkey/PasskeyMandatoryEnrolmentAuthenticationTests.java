/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2021
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package it.infn.mw.iam.test.multi_factor_authentication.passkey;

import static it.infn.mw.iam.api.account.multi_factor_authentication.passkey.DefaultIamPasskeyService.LAST_PASSKEY_MANDATORY_MESSAGE;
import static it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyController.BASE_URL;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;

import java.util.List;
import java.util.stream.Collectors;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import io.restassured.RestAssured;
import io.restassured.http.Cookie;
import io.restassured.response.Response;
import it.infn.mw.iam.core.IamNotificationType;
import it.infn.mw.iam.persistence.model.IamEmailNotification;
import it.infn.mw.iam.test.multi_factor_authentication.passkey.PasskeyTestAuthenticator.Algorithm;
import it.infn.mw.iam.test.util.annotation.IamRandomPortIntegrationTest;

/**
 * End to end exercise of the mandatory passkey policy for accounts without any factor, against a
 * running IAM: the password login lands on the enrolment page, the pre-authenticated user
 * registers a passkey as first factor and verifies it, and an administrative reset sends the
 * user back to enrolment at the next login
 */
@ExtendWith(SpringExtension.class)
@IamRandomPortIntegrationTest
@TestPropertySource(properties = {"mfa.passkey.enabled=true", "mfa.passkey.mandatory=true"})
public class PasskeyMandatoryEnrolmentAuthenticationTests
    extends PasskeyAuthenticationTestSupport {

  public static final String TEST_USERNAME = "test";
  public static final String TEST_PASSWORD = "password";
  public static final String TEST_UUID = "80e5fb8d-b7c8-451a-89ba-346ae278a66f";
  public static final String ADMIN_USERNAME = "admin";
  public static final String ADMIN_PASSWORD = "password";
  public static final String PASSKEYS_RESET_SUBJECT = "Passkeys reset";

  @AfterEach
  void cleanup() {
    cleanupPasskeysAndNotifications(TEST_USERNAME);
    cleanupPasskeysAndNotifications(ADMIN_USERNAME);
  }

  /**
   * Password login of a user who still has to enrol the mandatory passkey: returns the
   * pre-authenticated session, parked at the enrolment page
   */
  private Cookie loginExpectingEnrolment(String username, String password) {
    Cookie session = startAuthorization();
    Response loginResponse = login(session, username, password);
    assertThat(loginResponse.getStatusCode(), is(HttpStatus.FOUND.value()));
    assertThat(loginResponse.getHeader("Location"), is(activateUrl));
    return sessionAfter(loginResponse, session);
  }

  /**
   * Enrols a passkey from the enrolment page and completes the pending verification with it
   */
  private Cookie enrolAndVerify(Cookie session, PasskeyTestAuthenticator authenticator)
      throws Exception {
    // @formatter:off
    RestAssured.given()
        .cookie(session)
      .when()
        .get(activateUrl)
      .then()
        .statusCode(HttpStatus.OK.value())
        .body(containsString("activateMfa"));
    // @formatter:on
    registerPasskey(session, authenticator);

    String page = verifyPage(session);
    assertThat(page, containsString("passkey-verify-form"));
    assertThat(page, not(containsString("id=\"totp\"")));
    return assertVerificationSucceeded(
        verifyWithPasskey(session, csrfTokenFrom(page), assertion(session, authenticator, 1)),
        session);
  }

  private List<String> subjectsOf(IamNotificationType type) {
    return notificationRepository.findByNotificationType(type)
      .stream()
      .map(IamEmailNotification::getSubject)
      .collect(Collectors.toList());
  }

  @Test
  void userWithoutAnyFactorEnrolsAPasskeyAndVerifiesIt() throws Exception {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);

    Cookie session = loginExpectingEnrolment(TEST_USERNAME, TEST_PASSWORD);

    // Nothing but the enrolment is reachable before the first factor exists
    // @formatter:off
    RestAssured.given()
        .cookie(session)
        .redirects().follow(false)
      .when()
        .get(verifyUrl)
      .then()
        .statusCode(HttpStatus.OK.value())
        .body(not(containsString("passkey-verify-form")));
    // @formatter:on

    session = enrolAndVerify(session, authenticator);
    assertThat(passkeyRepository.findByAccountUsername(TEST_USERNAME), hasSize(1));

    // The authorization endpoint is reachable and the enrolment page is no longer imposed
    Response authorized = authorize(session);
    assertThat(authorized.getHeader("Location"), not(is(activateUrl)));
    assertThat(authorized.getHeader("Location"), not(is(loginUrl)));
    assertThat(authorized.getHeader("Location"), not(is(verifyUrl)));

    // The only passkey cannot be removed while passkeys are mandatory
    String uuid = passkeyRepository.findByAccountUsername(TEST_USERNAME).get(0).getUuid();
    // @formatter:off
    RestAssured.given().cookie(session)
      .when().delete(BASE_URL + "/" + uuid)
      .then()
        .statusCode(HttpStatus.BAD_REQUEST.value())
        .body("error", is(LAST_PASSKEY_MANDATORY_MESSAGE));
    // @formatter:on
    logout(session);

    // From now on the passkey is asked at every login
    session = loginExpectingVerification(TEST_USERNAME, TEST_PASSWORD);
    String csrf = csrfTokenFrom(verifyPage(session));
    session = assertVerificationSucceeded(
        verifyWithPasskey(session, csrf, assertion(session, authenticator, 2)), session);
    assertThat(authorize(session).getHeader("Location"), not(is(activateUrl)));
    assertThat(passkeyRepository.findByAccountUsername(TEST_USERNAME).get(0).getSignCount(),
        is(2L));
  }

  @Test
  void adminResetForcesANewEnrolmentAtTheNextLogin() throws Exception {
    PasskeyTestAuthenticator userKey = new PasskeyTestAuthenticator(Algorithm.ES256);
    PasskeyTestAuthenticator adminKey = new PasskeyTestAuthenticator(Algorithm.RS256);

    Cookie session = enrolAndVerify(loginExpectingEnrolment(TEST_USERNAME, TEST_PASSWORD), userKey);
    logout(session);

    // The administrator is subject to the same policy
    Cookie adminSession =
        enrolAndVerify(loginExpectingEnrolment(ADMIN_USERNAME, ADMIN_PASSWORD), adminKey);
    // @formatter:off
    RestAssured.given().cookie(adminSession)
      .when().delete(BASE_URL + "/reset/" + TEST_UUID)
      .then().statusCode(HttpStatus.NO_CONTENT.value());
    // @formatter:on
    assertThat(passkeyRepository.findByAccountUsername(TEST_USERNAME), empty());
    assertThat(passkeyRepository.findByAccountUsername(ADMIN_USERNAME), hasSize(1));
    assertThat(subjectsOf(IamNotificationType.MFA_DISABLE),
        hasItem(containsString(PASSKEYS_RESET_SUBJECT)));
    logout(adminSession);

    // The old passkey is gone: the user is sent to enrolment again and a new one is required
    session = loginExpectingEnrolment(TEST_USERNAME, TEST_PASSWORD);
    PasskeyTestAuthenticator replacement = new PasskeyTestAuthenticator(Algorithm.ES256);
    session = enrolAndVerify(session, replacement);
    assertThat(passkeyRepository.findByAccountUsername(TEST_USERNAME), hasSize(1));
    assertThat(passkeyRepository.findByAccountUsername(TEST_USERNAME).get(0).getCredentialId(),
        is(replacement.getCredentialIdBase64Url()));
    logout(session);

    session = loginExpectingVerification(TEST_USERNAME, TEST_PASSWORD);
    String csrf = csrfTokenFrom(verifyPage(session));
    assertVerificationFailed(verifyWithPasskey(session, csrf, assertion(session, userKey, 2)));
    assertVerificationSucceeded(verifyWithPasskey(session, csrf, assertion(session, replacement, 2)),
        session);
  }
}
