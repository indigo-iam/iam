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

import static it.infn.mw.iam.api.account.multi_factor_authentication.authenticator_app.AuthenticatorAppSettingsController.DISABLE_URL;
import static it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyController.BASE_URL;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;

import java.time.Instant;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import dev.samstevens.totp.code.DefaultCodeGenerator;
import io.restassured.RestAssured;
import io.restassured.http.Cookie;
import io.restassured.response.Response;
import it.infn.mw.iam.api.account.multi_factor_authentication.MultiFactorPolicy;
import it.infn.mw.iam.config.mfa.IamTotpMfaProperties;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;
import it.infn.mw.iam.test.multi_factor_authentication.passkey.PasskeyTestAuthenticator.Algorithm;
import it.infn.mw.iam.test.util.annotation.IamRandomPortIntegrationTest;
import it.infn.mw.iam.util.mfa.IamTotpMfaEncryptionAndDecryptionUtil;

/**
 * End to end exercise of the generic mandatory MFA policy (mfa.multi-factor-mandatory) with
 * passkeys enabled but not mandatory, against a running IAM: a user without any factor may enrol
 * a passkey instead of an authenticator app at the enrolment page, and a user who already owns
 * an authenticator app keeps using it without being forced to add a passkey
 */
@ExtendWith(SpringExtension.class)
@IamRandomPortIntegrationTest
// The test data TOTP secret is encrypted with the key of IamTotpMfaCommons.KEY_TO_ENCRYPT_DECRYPT
@TestPropertySource(properties = {"mfa.passkey.enabled=true", "mfa.multi-factor-mandatory=true",
    "mfa.password-to-encrypt-and-decrypt=define_me_please"})
public class PasskeyMultiFactorMandatoryAuthenticationTests
    extends PasskeyAuthenticationTestSupport {

  public static final String TEST_USERNAME = "test";
  public static final String TEST_PASSWORD = "password";
  public static final String TOTP_USERNAME = "test-with-mfa";
  public static final String TOTP_PASSWORD = "password";
  public static final long TOTP_ACCOUNT_ID = 1000L;
  private static final long TOTP_PERIOD_SECONDS = 30L;

  @Autowired
  IamTotpMfaRepository totpMfaRepository;

  @Autowired
  IamTotpMfaProperties totpMfaProperties;

  @AfterEach
  void cleanup() {
    cleanupPasskeysAndNotifications(TEST_USERNAME);
    cleanupPasskeysAndNotifications(TOTP_USERNAME);
  }

  private String currentTotp() throws Exception {
    IamTotpMfa totpMfa = totpMfaRepository.findByAccountId(TOTP_ACCOUNT_ID).orElseThrow();
    String secret = IamTotpMfaEncryptionAndDecryptionUtil.decryptSecret(totpMfa.getSecret(),
        totpMfaProperties.getPasswordToEncryptAndDecrypt());
    return new DefaultCodeGenerator().generate(secret,
        Math.floorDiv(Instant.now().getEpochSecond(), TOTP_PERIOD_SECONDS));
  }

  @Test
  void userWithoutAnyFactorMayEnrolAPasskeyInsteadOfAnAuthenticatorApp() throws Exception {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);

    // MFA is mandatory: the password login lands on the enrolment page
    Cookie session = startAuthorization();
    Response loginResponse = login(session, TEST_USERNAME, TEST_PASSWORD);
    assertThat(loginResponse.getStatusCode(), is(HttpStatus.FOUND.value()));
    assertThat(loginResponse.getHeader("Location"), is(activateUrl));
    session = sessionAfter(loginResponse, session);

    // @formatter:off
    RestAssured.given()
        .cookie(session)
      .when()
        .get(activateUrl)
      .then()
        .statusCode(HttpStatus.OK.value())
        .body(containsString("activateMfa"));
    // @formatter:on

    // The passkey is accepted as the first factor
    registerPasskey(session, authenticator);
    assertThat(passkeyRepository.findByAccountUsername(TEST_USERNAME), hasSize(1));

    String page = verifyPage(session);
    assertThat(page, containsString("passkey-verify-form"));
    assertThat(page, not(containsString("id=\"totp\"")));
    session = assertVerificationSucceeded(
        verifyWithPasskey(session, csrfTokenFrom(page), assertion(session, authenticator, 1)),
        session);

    // The passkey satisfies the policy: no enrolment is imposed anymore
    Response authorized = authorize(session);
    assertThat(authorized.getHeader("Location"), not(is(activateUrl)));
    assertThat(authorized.getHeader("Location"), not(is(loginUrl)));
    // @formatter:off
    RestAssured.given().cookie(session)
      .when().get(BASE_URL)
      .then().statusCode(HttpStatus.OK.value()).body("", hasSize(1));
    // The enrolment page is not for users who already own a factor
    RestAssured.given().cookie(session).redirects().follow(false)
      .when().get(activateUrl)
      .then().statusCode(HttpStatus.FORBIDDEN.value());
    // @formatter:on
    logout(session);

    // Next login: straight to the verification page, the passkey completes it
    session = loginExpectingVerification(TEST_USERNAME, TEST_PASSWORD);
    page = verifyPage(session);
    assertThat(page, containsString("passkey-verify-form"));
    assertThat(page, not(containsString("id=\"totp\"")));
    session = assertVerificationSucceeded(
        verifyWithPasskey(session, csrfTokenFrom(page), assertion(session, authenticator, 2)),
        session);
    assertThat(authorize(session).getHeader("Location"), not(is(activateUrl)));
    assertThat(passkeyRepository.findByAccountUsername(TEST_USERNAME).get(0).getSignCount(),
        is(2L));
  }

  @Test
  void authenticatorAppUserIsNotForcedToEnrolAPasskey() throws Exception {
    Cookie session = loginExpectingVerification(TOTP_USERNAME, TOTP_PASSWORD);
    String page = verifyPage(session);
    assertThat(page, containsString("id=\"totp\""));
    assertThat(page, not(containsString("passkey-verify-form")));

    session = assertVerificationSucceeded(
        verifyWithTotp(session, csrfTokenFrom(page), currentTotp()), session);
    assertThat(authorize(session).getHeader("Location"), not(is(activateUrl)));

    // The fully authenticated user may add a passkey as an additional factor...
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    registerPasskey(session, authenticator);
    logout(session);

    // ...and is then offered both factors
    session = loginExpectingVerification(TOTP_USERNAME, TOTP_PASSWORD);
    page = verifyPage(session);
    assertThat(page, containsString("id=\"totp\""));
    assertThat(page, containsString("passkey-verify-form"));
    session = assertVerificationSucceeded(
        verifyWithPasskey(session, csrfTokenFrom(page), assertion(session, authenticator, 1)),
        session);

    // Multi-factor authentication is mandatory: the passkey can go while the authenticator app
    // remains (the app itself proves the removal)...
    String uuid = passkeyRepository.findByAccountUsername(TOTP_USERNAME).get(0).getUuid();
    // @formatter:off
    removePasskey(session, uuid, totpProof(currentTotp())).then()
      .statusCode(HttpStatus.NO_CONTENT.value());
    // ...but the authenticator app, now the last factor, cannot be disabled
    RestAssured.given().cookie(session).formParam("code", currentTotp())
      .when().post(DISABLE_URL)
      .then()
        .statusCode(HttpStatus.BAD_REQUEST.value())
        .body("error", is(MultiFactorPolicy.LAST_FACTOR_MESSAGE));
    // @formatter:on
    assertThat(passkeyRepository.findByAccountUsername(TOTP_USERNAME), hasSize(0));
    assertThat(totpMfaRepository.findByAccountId(TOTP_ACCOUNT_ID).isPresent(), is(true));
  }
}
