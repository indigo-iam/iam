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

import static it.infn.mw.iam.api.account.multi_factor_authentication.authenticator_app.AuthenticatorAppSettingsController.ADD_SECRET_URL;
import static it.infn.mw.iam.api.account.multi_factor_authentication.authenticator_app.AuthenticatorAppSettingsController.ENABLE_URL;
import static it.infn.mw.iam.api.account.multi_factor_authentication.passkey.DefaultIamPasskeyService.BAD_REMOVAL_TOTP_MESSAGE;
import static it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyController.AUTHENTICATION_OPTIONS_URL;
import static it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyController.BASE_URL;
import static it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyController.REGISTRATION_OPTIONS_URL;
import static it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyController.REGISTRATION_URL;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;

import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import dev.samstevens.totp.code.DefaultCodeGenerator;
import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.http.Cookie;
import io.restassured.response.Response;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyAssertionDTO;
import it.infn.mw.iam.core.IamNotificationType;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamEmailNotification;
import it.infn.mw.iam.persistence.model.IamPasskey;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;
import it.infn.mw.iam.test.multi_factor_authentication.passkey.PasskeyTestAuthenticator.Algorithm;
import it.infn.mw.iam.test.util.annotation.IamRandomPortIntegrationTest;

/**
 * End to end exercise of an account owning both an authenticator app and a passkey, against a
 * running IAM with the default (non mandatory) MFA policy: enrolment of both factors through the
 * REST API, verification with either factor at /iam/verify, the enrolment restrictions imposed on
 * pre-authenticated users and the administrative reset of the passkeys
 */
@ExtendWith(SpringExtension.class)
@IamRandomPortIntegrationTest
@TestPropertySource(properties = {"mfa.passkey.enabled=true",
    "mfa.password-to-encrypt-and-decrypt=define_me_please"})
public class PasskeyAndTotpAuthenticationTests extends PasskeyAuthenticationTestSupport {

  public static final String TEST_USERNAME = "test";
  public static final String TEST_PASSWORD = "password";
  public static final String TEST_UUID = "80e5fb8d-b7c8-451a-89ba-346ae278a66f";
  public static final String ADMIN_USERNAME = "admin";
  public static final String ADMIN_PASSWORD = "password";

  public static final String TOTP_ENABLED_SUBJECT = "Multi-factor authentication (MFA) enabled";
  public static final String PASSKEY_REGISTERED_SUBJECT = "Passkey registered";
  public static final String PASSKEYS_RESET_SUBJECT = "Passkeys reset";
  public static final String PASSKEY_REMOVED_SUBJECT = "Passkey removed";

  private static final long TOTP_PERIOD_SECONDS = 30L;
  private static final int TOTP_MODULUS = 1_000_000;

  @Autowired
  IamAccountRepository accountRepository;

  @Autowired
  IamTotpMfaRepository totpMfaRepository;

  @AfterEach
  void cleanup() {
    cleanupPasskeysAndNotifications(TEST_USERNAME);
    cleanupPasskeysAndNotifications(ADMIN_USERNAME);
    // The authenticator app enrolled by the tests must not survive them: the seed has no TOTP
    // secret for the test user
    IamAccount account = accountRepository.findByUsername(TEST_USERNAME).orElseThrow();
    totpMfaRepository.findByAccountId(account.getId()).ifPresent(totpMfaRepository::delete);
  }

  private String totpFor(String secret) throws Exception {
    return new DefaultCodeGenerator().generate(secret,
        Math.floorDiv(Instant.now().getEpochSecond(), TOTP_PERIOD_SECONDS));
  }

  /**
   * A code that is certainly not the current one: the current code shifted by one
   */
  private String wrongTotpFor(String secret) throws Exception {
    int wrong = (Integer.parseInt(totpFor(secret)) + 1) % TOTP_MODULUS;
    return String.format("%06d", wrong);
  }

  /**
   * Enrols the authenticator app through the REST API, as the dashboard does: the secret is
   * bound to the account and then activated with a valid code
   */
  private String enrolAuthenticatorApp(Cookie session) throws Exception {
    // @formatter:off
    String secret = RestAssured.given()
        .cookie(session)
      .when()
        .put(ADD_SECRET_URL)
      .then()
        .statusCode(HttpStatus.OK.value())
        .body("secret", notNullValue())
        .extract().path("secret");

    RestAssured.given()
        .cookie(session)
        .formParam("code", totpFor(secret))
      .when()
        .post(ENABLE_URL)
      .then()
        .statusCode(HttpStatus.OK.value());
    // @formatter:on
    return secret;
  }

  private List<String> subjectsOf(IamNotificationType type) {
    return notificationRepository.findByNotificationType(type)
      .stream()
      .map(IamEmailNotification::getSubject)
      .collect(Collectors.toList());
  }

  @Test
  void bothFactorsAreOfferedAndEitherOneCompletesTheLogin() throws Exception {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);

    // Enrolment of both factors requires a fully authenticated session
    Cookie session = loginWithoutSecondFactor(TEST_USERNAME, TEST_PASSWORD);
    String secret = enrolAuthenticatorApp(session);
    registerPasskey(session, authenticator);
    assertThat(passkeyRepository.findByAccountUsername(TEST_USERNAME), hasSize(1));

    // Both enrolments queue an e-mail
    assertThat(subjectsOf(IamNotificationType.MFA_ENABLE),
        hasItems(containsString(TOTP_ENABLED_SUBJECT), containsString(PASSKEY_REGISTERED_SUBJECT)));
    logout(session);

    // The verification page offers both factors
    session = loginExpectingVerification(TEST_USERNAME, TEST_PASSWORD);
    String page = verifyPage(session);
    assertThat(page, containsString("id=\"totp\""));
    assertThat(page, containsString("passkey-verify-form"));
    String csrf = csrfTokenFrom(page);

    // The authenticator app completes the login...
    session = assertVerificationSucceeded(verifyWithTotp(session, csrf, totpFor(secret)), session);
    // ...and the passkey is untouched
    IamPasskey stored = passkeyRepository.findByAccountUsername(TEST_USERNAME).get(0);
    assertThat(stored.getSignCount(), is(0L));
    logout(session);

    // The passkey completes the login as well
    session = loginExpectingVerification(TEST_USERNAME, TEST_PASSWORD);
    csrf = csrfTokenFrom(verifyPage(session));
    session = assertVerificationSucceeded(
        verifyWithPasskey(session, csrf, assertion(session, authenticator, 1)), session);
    stored = passkeyRepository.findByAccountUsername(TEST_USERNAME).get(0);
    assertThat(stored.getSignCount(), is(1L));
    assertThat(stored.getLastUsedTime(), notNullValue());
    long firstUse = stored.getLastUsedTime().getTime();
    assertThat(firstUse, greaterThan(0L));
    logout(session);

    // A wrong code does not consume the login: the passkey still completes it
    session = loginExpectingVerification(TEST_USERNAME, TEST_PASSWORD);
    csrf = csrfTokenFrom(verifyPage(session));
    assertVerificationFailed(verifyWithTotp(session, csrf, wrongTotpFor(secret)));
    assertThat(verifyPage(session), containsString("passkey-verify-form"));
    session = assertVerificationSucceeded(
        verifyWithPasskey(session, csrf, assertion(session, authenticator, 2)), session);
    stored = passkeyRepository.findByAccountUsername(TEST_USERNAME).get(0);
    assertThat(stored.getSignCount(), is(2L));
    assertThat(stored.getLastUsedTime().getTime(), not(is(0L)));
    logout(session);

    // A valid code after a failed passkey attempt completes the login too
    session = loginExpectingVerification(TEST_USERNAME, TEST_PASSWORD);
    csrf = csrfTokenFrom(verifyPage(session));
    PasskeyAssertionDTO tampered = assertion(session, authenticator, 3);
    tampered.getResponse()
      .setSignature(PasskeyTestAuthenticator.base64Url(PasskeyTestAuthenticator.randomBytes(70)));
    assertVerificationFailed(verifyWithPasskey(session, csrf, tampered));
    session = assertVerificationSucceeded(verifyWithTotp(session, csrf, totpFor(secret)), session);

    // The failed passkey attempt did not touch the stored counter
    stored = passkeyRepository.findByAccountUsername(TEST_USERNAME).get(0);
    assertThat(stored.getSignCount(), is(2L));

    // Once fully authenticated the verification page is gone
    // @formatter:off
    RestAssured.given()
        .cookie(session)
        .redirects().follow(false)
      .when()
        .get(verifyUrl)
      .then()
        .statusCode(HttpStatus.FORBIDDEN.value());
    // @formatter:on
  }

  @Test
  void preAuthenticatedUserCannotEnrolAnotherFactorBeforeVerifying() throws Exception {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);

    Cookie session = loginWithoutSecondFactor(TEST_USERNAME, TEST_PASSWORD);
    registerPasskey(session, authenticator);
    logout(session);

    // Password verified, second factor pending: no new factor can be added...
    session = loginExpectingVerification(TEST_USERNAME, TEST_PASSWORD);
    // @formatter:off
    RestAssured.given().cookie(session)
      .when().post(REGISTRATION_OPTIONS_URL)
      .then().statusCode(HttpStatus.FORBIDDEN.value());
    RestAssured.given().cookie(session).contentType(ContentType.JSON).body("{}")
      .when().post(REGISTRATION_URL)
      .then().statusCode(HttpStatus.FORBIDDEN.value());
    RestAssured.given().cookie(session)
      .when().put(ADD_SECRET_URL)
      .then().statusCode(HttpStatus.FORBIDDEN.value());
    RestAssured.given().cookie(session).formParam("code", "123456")
      .when().post(ENABLE_URL)
      .then().statusCode(HttpStatus.FORBIDDEN.value());
    // ...nor can the passkeys be listed or removed
    RestAssured.given().cookie(session)
      .when().get(BASE_URL)
      .then().statusCode(HttpStatus.FORBIDDEN.value());
    // @formatter:on
    assertThat(passkeyRepository.findByAccountUsername(TEST_USERNAME), hasSize(1));
    IamAccount account = accountRepository.findByUsername(TEST_USERNAME).orElseThrow();
    assertThat(totpMfaRepository.findByAccountId(account.getId()).isPresent(), is(false));

    // ...while the assertion options for the pending verification are available
    assertThat(assertionOptions(session).getAllowCredentials(), hasSize(1));

    String csrf = csrfTokenFrom(verifyPage(session));
    session = assertVerificationSucceeded(
        verifyWithPasskey(session, csrf, assertion(session, authenticator, 1)), session);

    // Once the second factor is verified, new factors can be enrolled...
    // @formatter:off
    RestAssured.given().cookie(session)
      .when().post(REGISTRATION_OPTIONS_URL)
      .then().statusCode(HttpStatus.OK.value());
    RestAssured.given().cookie(session)
      .when().put(ADD_SECRET_URL)
      .then().statusCode(HttpStatus.OK.value()).body("secret", notNullValue());
    RestAssured.given().cookie(session)
      .when().get(BASE_URL)
      .then().statusCode(HttpStatus.OK.value()).body("", hasSize(1));
    // ...and the step-up options are no longer available
    RestAssured.given().cookie(session)
      .when().post(AUTHENTICATION_OPTIONS_URL)
      .then().statusCode(HttpStatus.FORBIDDEN.value());
    // @formatter:on

    PasskeyTestAuthenticator second = new PasskeyTestAuthenticator(Algorithm.RS256);
    registrationResponse(session, second, false, "Second key").then()
      .statusCode(HttpStatus.CREATED.value());
    assertThat(passkeyRepository.findByAccountUsername(TEST_USERNAME), hasSize(2));
  }

  @Test
  void adminResetRemovesEveryPasskeyAndTheNextLoginIsPasswordOnly() throws Exception {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    PasskeyTestAuthenticator other = new PasskeyTestAuthenticator(Algorithm.RS256);

    Cookie session = loginWithoutSecondFactor(TEST_USERNAME, TEST_PASSWORD);
    registerPasskey(session, authenticator);
    registrationResponse(session, other, false, "Other key").then()
      .statusCode(HttpStatus.CREATED.value());
    assertThat(passkeyRepository.findByAccountUsername(TEST_USERNAME), hasSize(2));
    logout(session);

    // The login now requires the second factor
    session = loginExpectingVerification(TEST_USERNAME, TEST_PASSWORD);
    logout(session);

    // The user itself cannot reset the passkeys of an account...
    session = loginExpectingVerification(TEST_USERNAME, TEST_PASSWORD);
    String csrf = csrfTokenFrom(verifyPage(session));
    session = assertVerificationSucceeded(
        verifyWithPasskey(session, csrf, assertion(session, authenticator, 1, false)), session);
    // @formatter:off
    RestAssured.given().cookie(session)
      .when().delete(BASE_URL + "/reset/" + TEST_UUID)
      .then().statusCode(HttpStatus.FORBIDDEN.value());
    // @formatter:on
    assertThat(passkeyRepository.findByAccountUsername(TEST_USERNAME), hasSize(2));
    logout(session);

    // ...an administrator can
    Cookie adminSession = loginWithoutSecondFactor(ADMIN_USERNAME, ADMIN_PASSWORD);
    // @formatter:off
    RestAssured.given().cookie(adminSession)
      .when().delete(BASE_URL + "/reset/" + TEST_UUID)
      .then().statusCode(HttpStatus.NO_CONTENT.value());
    // @formatter:on
    assertThat(passkeyRepository.findByAccountUsername(TEST_USERNAME), empty());
    assertThat(subjectsOf(IamNotificationType.MFA_DISABLE),
        hasItems(containsString(PASSKEYS_RESET_SUBJECT)));
    logout(adminSession);

    // The next login of the user is password only
    session = loginWithoutSecondFactor(TEST_USERNAME, TEST_PASSWORD);
    // @formatter:off
    RestAssured.given().cookie(session)
      .when().get(BASE_URL)
      .then().statusCode(HttpStatus.OK.value()).body("", hasSize(0));
    // @formatter:on
  }

  @Test
  void theAuthenticatorAppProvesTheRemovalOfAPasskey() throws Exception {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);

    Cookie session = loginWithoutSecondFactor(TEST_USERNAME, TEST_PASSWORD);
    String secret = enrolAuthenticatorApp(session);
    registerPasskey(session, authenticator);
    String uuid = passkeyRepository.findByAccountUsername(TEST_USERNAME).get(0).getUuid();

    // A wrong code is refused, a valid one removes the passkey
    // @formatter:off
    removePasskey(session, uuid, totpProof(wrongTotpFor(secret))).then()
      .statusCode(HttpStatus.BAD_REQUEST.value())
      .body("error", is(BAD_REMOVAL_TOTP_MESSAGE));
    removePasskey(session, uuid, totpProof(totpFor(secret))).then()
      .statusCode(HttpStatus.NO_CONTENT.value());
    // @formatter:on
    assertThat(passkeyRepository.findByAccountUsername(TEST_USERNAME), empty());
    assertThat(subjectsOf(IamNotificationType.MFA_DISABLE),
        hasItems(containsString(PASSKEY_REMOVED_SUBJECT)));

    // The authenticator app is the only factor left
    logout(session);
    session = loginExpectingVerification(TEST_USERNAME, TEST_PASSWORD);
    String csrf = csrfTokenFrom(verifyPage(session));
    assertVerificationSucceeded(verifyWithTotp(session, csrf, totpFor(secret)), session);
  }
}
