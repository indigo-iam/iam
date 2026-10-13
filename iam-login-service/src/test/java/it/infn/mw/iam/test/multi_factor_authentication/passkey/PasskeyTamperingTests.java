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

import static it.infn.mw.iam.test.multi_factor_authentication.passkey.PasskeyTestAuthenticator.base64Url;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import io.restassured.http.Cookie;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyAssertionDTO;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamPasskey;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.config.ClockConfig;
import it.infn.mw.iam.test.multi_factor_authentication.passkey.PasskeyTestAuthenticator.Algorithm;
import it.infn.mw.iam.test.util.annotation.IamRandomPortIntegrationTest;
import it.infn.mw.iam.test.util.clock.MutableClock;

/**
 * End to end exercise of the assertion checks performed at /iam/verify against a running IAM
 * configured with mandatory user verification and the shortest allowed challenge lifetime:
 * replayed, expired, forged and borrowed assertions are all rejected and leave the user on the
 * verification page, while a fresh and valid assertion still completes the login afterwards
 */
@ExtendWith(SpringExtension.class)
@IamRandomPortIntegrationTest
@Import(ClockConfig.class)
@TestPropertySource(properties = {"mfa.passkey.enabled=true",
    "mfa.passkey.user-verification=required", "mfa.passkey.challenge-timeout-seconds=30"})
public class PasskeyTamperingTests extends PasskeyAuthenticationTestSupport {

  public static final String TEST_USERNAME = "test";
  public static final String TEST_PASSWORD = "password";
  public static final String OTHER_USERNAME = "admin";
  public static final String EVIL_ORIGIN = "https://evil.example.org";
  public static final String EVIL_RP_ID = "evil.example.org";
  private static final int CHALLENGE_TIMEOUT_SECONDS = 30;

  @Autowired
  IamAccountRepository accountRepository;

  @Autowired
  Clock clock;

  private PasskeyTestAuthenticator authenticator;
  private Cookie session;
  private String csrf;

  @BeforeEach
  void registerAndLogin() throws Exception {
    assertThat(clock, instanceOf(MutableClock.class));
    authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    Cookie enrolment = loginWithoutSecondFactor(TEST_USERNAME, TEST_PASSWORD);
    registerPasskey(enrolment, authenticator, true);
    logout(enrolment);

    session = loginExpectingVerification(TEST_USERNAME, TEST_PASSWORD);
    csrf = csrfTokenFrom(verifyPage(session));
  }

  @AfterEach
  void cleanup() {
    cleanupPasskeysAndNotifications(TEST_USERNAME);
    cleanupPasskeysAndNotifications(OTHER_USERNAME);
  }

  private IamPasskey storedPasskey() {
    return passkeyRepository.findByAccountUsername(TEST_USERNAME).get(0);
  }

  private void assertNeverUsed() {
    IamPasskey stored = storedPasskey();
    assertThat(stored.getSignCount(), is(0L));
    assertThat(stored.getLastUsedTime(), nullValue());
  }

  /**
   * After a rejected assertion the session is still pre-authenticated and a fresh ceremony
   * completes the login
   */
  private void assertFreshAssertionCompletesTheLogin(long signCount) throws Exception {
    assertThat(verifyPage(session), containsString("passkey-verify-form"));
    session = assertVerificationSucceeded(
        verifyWithPasskey(session, csrf, assertion(session, authenticator, signCount, true)),
        session);
    IamPasskey stored = storedPasskey();
    assertThat(stored.getSignCount(), is(signCount));
    assertThat(stored.getLastUsedTime(), notNullValue());
  }

  @Test
  void assertionWithoutUserVerificationIsRejectedWhenRequired() throws Exception {
    assertVerificationFailed(
        verifyWithPasskey(session, csrf, assertion(session, authenticator, 1, false)));
    assertNeverUsed();
    assertFreshAssertionCompletesTheLogin(2);
  }

  @Test
  void registrationWithoutUserVerificationIsRejectedWhenRequired() throws Exception {
    // Completed as the fully authenticated user, who may add a second passkey
    session = assertVerificationSucceeded(
        verifyWithPasskey(session, csrf, assertion(session, authenticator, 1, true)), session);
    PasskeyTestAuthenticator second = new PasskeyTestAuthenticator(Algorithm.RS256);
    registrationResponse(session, second, false, "No UV").then()
      .statusCode(HttpStatus.BAD_REQUEST.value())
      .body("error", containsString("Passkey registration failed"));
    assertThat(passkeyRepository.findByAccountUsername(TEST_USERNAME), hasSize(1));
    registrationResponse(session, second, true, "With UV").then()
      .statusCode(HttpStatus.CREATED.value());
    assertThat(passkeyRepository.findByAccountUsername(TEST_USERNAME), hasSize(2));
  }

  @Test
  void assertionForAnotherOriginIsRejected() throws Exception {
    String challenge = assertionOptions(session).getChallenge();
    assertVerificationFailed(verifyWithPasskey(session, csrf,
        assertionFor(authenticator, challenge, EVIL_ORIGIN, true, 1, null)));
    assertNeverUsed();
    assertFreshAssertionCompletesTheLogin(2);
  }

  @Test
  void assertionForAnotherRelyingPartyIsRejected() throws Exception {
    String challenge = assertionOptions(session).getChallenge();
    assertVerificationFailed(verifyWithPasskey(session, csrf, assertionFor(authenticator,
        EVIL_RP_ID, GET_TYPE, challenge, TEST_ORIGIN, true, 1, null)));
    assertNeverUsed();
    assertFreshAssertionCompletesTheLogin(2);
  }

  @Test
  void registrationClientDataIsNotAcceptedAsAnAssertion() throws Exception {
    String challenge = assertionOptions(session).getChallenge();
    assertVerificationFailed(verifyWithPasskey(session, csrf, assertionFor(authenticator,
        TEST_RP_ID, CREATE_TYPE, challenge, TEST_ORIGIN, true, 1, null)));
    assertNeverUsed();
    assertFreshAssertionCompletesTheLogin(2);
  }

  @Test
  void signatureOfAnotherAuthenticatorIsRejected() throws Exception {
    PasskeyTestAuthenticator impostor = new PasskeyTestAuthenticator(Algorithm.ES256);
    String challenge = assertionOptions(session).getChallenge();
    // The impostor presents the registered credential id, signed with its own key
    PasskeyAssertionDTO forged =
        assertionFor(impostor, challenge, TEST_ORIGIN, true, 1, null);
    forged.setId(authenticator.getCredentialIdBase64Url());
    forged.setRawId(authenticator.getCredentialIdBase64Url());
    assertVerificationFailed(verifyWithPasskey(session, csrf, forged));
    assertNeverUsed();
    assertFreshAssertionCompletesTheLogin(2);
  }

  @Test
  void credentialOfAnotherAccountIsRejected() throws Exception {
    // A credential registered on another account, presented with a valid signature
    PasskeyTestAuthenticator borrowed = new PasskeyTestAuthenticator(Algorithm.ES256);
    IamAccount other = accountRepository.findByUsername(OTHER_USERNAME).orElseThrow();
    passkeyRepository.save(registeredPasskey(other, borrowed, clock.instant()));

    // Only the credentials of the account are offered
    assertThat(assertionOptions(session).getAllowCredentials(), hasSize(1));
    String challenge = assertionOptions(session).getChallenge();
    assertVerificationFailed(verifyWithPasskey(session, csrf,
        assertionFor(borrowed, challenge, TEST_ORIGIN, true, 1, null)));
    assertNeverUsed();
    IamPasskey foreign = passkeyRepository.findByAccountUsername(OTHER_USERNAME).get(0);
    assertThat(foreign.getSignCount(), is(0L));
    assertThat(foreign.getLastUsedTime(), nullValue());
    assertFreshAssertionCompletesTheLogin(2);
  }

  @Test
  void userHandleOfAnotherAccountIsRejected() throws Exception {
    IamAccount other = accountRepository.findByUsername(OTHER_USERNAME).orElseThrow();
    String foreignHandle = base64Url(other.getUuid().getBytes(StandardCharsets.UTF_8));
    String challenge = assertionOptions(session).getChallenge();
    assertVerificationFailed(verifyWithPasskey(session, csrf,
        assertionFor(authenticator, challenge, TEST_ORIGIN, true, 1, foreignHandle)));
    assertNeverUsed();

    // The handle of the account itself is accepted
    IamAccount own = accountRepository.findByUsername(TEST_USERNAME).orElseThrow();
    String ownHandle = base64Url(own.getUuid().getBytes(StandardCharsets.UTF_8));
    challenge = assertionOptions(session).getChallenge();
    session = assertVerificationSucceeded(verifyWithPasskey(session, csrf,
        assertionFor(authenticator, challenge, TEST_ORIGIN, true, 2, ownHandle)), session);
    assertThat(storedPasskey().getSignCount(), is(2L));
  }

  @Test
  void assertionWithoutAnIssuedChallengeIsRejected() throws Exception {
    String invented = base64Url(PasskeyTestAuthenticator.randomBytes(32));
    assertVerificationFailed(verifyWithPasskey(session, csrf,
        assertionFor(authenticator, invented, TEST_ORIGIN, true, 1, null)));
    assertNeverUsed();
    assertFreshAssertionCompletesTheLogin(2);
  }

  @Test
  void challengeCannotBeReusedAcrossLogins() throws Exception {
    PasskeyAssertionDTO first = assertion(session, authenticator, 1, true);
    String usedChallenge = extractChallenge(first);
    session = assertVerificationSucceeded(verifyWithPasskey(session, csrf, first), session);
    logout(session);

    session = loginExpectingVerification(TEST_USERNAME, TEST_PASSWORD);
    csrf = csrfTokenFrom(verifyPage(session));
    // A challenge is pending in the new session, but the assertion answers the old one
    assertionOptions(session);
    assertVerificationFailed(verifyWithPasskey(session, csrf,
        assertionFor(authenticator, usedChallenge, TEST_ORIGIN, true, 2, null)));
    // The very same assertion that worked before is useless as well
    assertVerificationFailed(verifyWithPasskey(session, csrf, first));
    assertThat(storedPasskey().getSignCount(), is(1L));
    assertFreshAssertionCompletesTheLogin(3);
  }

  @Test
  void signatureCounterMustIncrease() throws Exception {
    session = assertVerificationSucceeded(
        verifyWithPasskey(session, csrf, assertion(session, authenticator, 5, true)), session);
    assertThat(storedPasskey().getSignCount(), is(5L));
    logout(session);

    // A cloned authenticator replays the counter
    session = loginExpectingVerification(TEST_USERNAME, TEST_PASSWORD);
    csrf = csrfTokenFrom(verifyPage(session));
    assertVerificationFailed(
        verifyWithPasskey(session, csrf, assertion(session, authenticator, 5, true)));
    assertVerificationFailed(
        verifyWithPasskey(session, csrf, assertion(session, authenticator, 4, true)));
    assertThat(storedPasskey().getSignCount(), is(5L));
    assertFreshAssertionCompletesTheLogin(6);
  }

  @Test
  void expiredChallengeIsRejected() throws Exception {
    MutableClock mutableClock = (MutableClock) clock;
    PasskeyAssertionDTO late = assertion(session, authenticator, 1, true);
    mutableClock.advance(Duration.ofSeconds(CHALLENGE_TIMEOUT_SECONDS + 1));
    assertVerificationFailed(verifyWithPasskey(session, csrf, late));
    assertNeverUsed();

    // A challenge issued after the clock moved is valid for another lifetime
    PasskeyAssertionDTO inTime = assertion(session, authenticator, 2, true);
    mutableClock.advance(Duration.ofSeconds(CHALLENGE_TIMEOUT_SECONDS - 1));
    session = assertVerificationSucceeded(verifyWithPasskey(session, csrf, inTime), session);
    assertThat(storedPasskey().getSignCount(), is(2L));
  }
}
