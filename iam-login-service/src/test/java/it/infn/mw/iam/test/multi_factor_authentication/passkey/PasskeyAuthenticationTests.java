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

import static it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyController.REGISTRATION_OPTIONS_URL;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import io.restassured.RestAssured;
import io.restassured.http.Cookie;
import io.restassured.response.Response;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyAssertionDTO;
import it.infn.mw.iam.persistence.model.IamPasskey;
import it.infn.mw.iam.test.multi_factor_authentication.passkey.PasskeyTestAuthenticator.Algorithm;
import it.infn.mw.iam.test.util.annotation.IamRandomPortIntegrationTest;

/**
 * End to end exercise of the passkey login flow against a running IAM: a user without MFA
 * registers a passkey through the API, logs out, logs in again and is asked for the second
 * factor, which is provided as a WebAuthn assertion at /iam/verify
 */
@ExtendWith(SpringExtension.class)
@IamRandomPortIntegrationTest
@TestPropertySource(properties = {"mfa.passkey.enabled=true"})
public class PasskeyAuthenticationTests extends PasskeyAuthenticationTestSupport {

  public static final String TEST_USERNAME = "test";
  public static final String TEST_PASSWORD = "password";

  @AfterEach
  void cleanup() {
    cleanupPasskeysAndNotifications(TEST_USERNAME);
  }

  @Test
  void passkeyIsRequiredAtLoginOnceRegisteredAndCompletesAuthentication() throws Exception {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);

    // Without MFA, the login completes and returns to the authorization endpoint
    Cookie session = startAuthorization();
    Response loginResponse = login(session, TEST_USERNAME, TEST_PASSWORD);
    assertThat(loginResponse.getStatusCode(), is(HttpStatus.FOUND.value()));
    assertThat(loginResponse.getHeader("Location"), containsString("/authorize"));
    session = sessionAfter(loginResponse, session);

    registerPasskey(session, authenticator);
    assertThat(passkeyRepository.findByAccountUsername(TEST_USERNAME), hasSize(1));

    logout(session);

    // With a passkey registered, the login is pre-authenticated and asks for the second factor
    session = startAuthorization();
    loginResponse = login(session, TEST_USERNAME, TEST_PASSWORD);
    assertThat(loginResponse.getStatusCode(), is(HttpStatus.FOUND.value()));
    assertThat(loginResponse.getHeader("Location"), is(verifyUrl));
    session = sessionAfter(loginResponse, session);

    String page = verifyPage(session);
    assertThat(page, containsString("passkey-verify-form"));
    String csrf = csrfTokenFrom(page);

    // A bad assertion is rejected and the user stays on the verification page
    PasskeyAssertionDTO tampered = assertion(session, authenticator, 1);
    tampered.getResponse().setSignature(
        PasskeyTestAuthenticator.base64Url(PasskeyTestAuthenticator.randomBytes(70)));
    Response failed = verifyWithPasskey(session, csrf, tampered);
    assertThat(failed.getStatusCode(), is(HttpStatus.FOUND.value()));
    assertThat(failed.getHeader("Location"), containsString("/iam/verify?error=failure"));

    // The challenge was consumed by the failed attempt: a valid assertion for it is useless
    PasskeyAssertionDTO stale = assertionFor(authenticator,
        extractChallenge(tampered), TEST_ORIGIN, false, 2, null);
    Response replay = verifyWithPasskey(session, csrf, stale);
    assertThat(replay.getHeader("Location"), containsString("/iam/verify?error=failure"));

    // A fresh challenge and a valid assertion complete the authentication
    PasskeyAssertionDTO valid = assertion(session, authenticator, 3);
    Response verified = verifyWithPasskey(session, csrf, valid);
    assertThat(verified.getStatusCode(), is(HttpStatus.FOUND.value()));
    assertThat(verified.getHeader("Location"), containsString("/authorize"));
    // The session id is renewed by the step-up
    assertThat(verified.getDetailedCookie("JSESSIONID"), notNullValue());
    assertThat(verified.getDetailedCookie("JSESSIONID").getValue(), not(is(session.getValue())));
    session = sessionAfter(verified, session);

    IamPasskey stored = passkeyRepository.findByAccountUsername(TEST_USERNAME).get(0);
    assertThat(stored.getSignCount(), is(3L));
    assertThat(stored.getLastUsedTime(), notNullValue());
    assertThat(stored.getLastUsedTime().getTime(), greaterThan(0L));

    // The verification page is no longer reachable by the fully authenticated user
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
  void passkeyEndpointsRequireAuthentication() {
    // @formatter:off
    RestAssured.given()
        .redirects().follow(false)
      .when()
        .post(REGISTRATION_OPTIONS_URL)
      .then()
        .statusCode(HttpStatus.UNAUTHORIZED.value());
    // @formatter:on
    assertThat(passkeyRepository.findByAccountUsername(TEST_USERNAME), empty());
  }
}
