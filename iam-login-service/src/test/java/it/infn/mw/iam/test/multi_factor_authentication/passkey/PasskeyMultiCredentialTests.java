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

import static it.infn.mw.iam.api.account.multi_factor_authentication.passkey.DefaultIamPasskeyService.CREDENTIAL_ALREADY_REGISTERED_MESSAGE;
import static it.infn.mw.iam.api.account.multi_factor_authentication.passkey.DefaultIamPasskeyService.LIMIT_EXCEEDED_MESSAGE;
import static it.infn.mw.iam.api.account.multi_factor_authentication.passkey.DefaultIamPasskeyService.REMOVAL_PROOF_REQUIRED_MESSAGE;
import static it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyController.BASE_URL;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

import java.util.List;
import java.util.stream.Collectors;

import com.fasterxml.jackson.core.type.TypeReference;

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
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyAssertionOptionsDTO;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyCredentialDescriptorDTO;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyDTO;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyRemovalDTO;
import it.infn.mw.iam.core.IamNotificationType;
import it.infn.mw.iam.persistence.model.IamEmailNotification;
import it.infn.mw.iam.persistence.model.IamPasskey;
import it.infn.mw.iam.test.multi_factor_authentication.passkey.PasskeyTestAuthenticator.Algorithm;
import it.infn.mw.iam.test.util.annotation.IamRandomPortIntegrationTest;

/**
 * End to end exercise of an account owning more than one passkey, against a running IAM with a
 * limit of two credentials per account: either authenticator completes the login, a removed
 * passkey stops working, the limit is enforced by the registration endpoint and a challenge does
 * not survive the session it was issued to
 */
@ExtendWith(SpringExtension.class)
@IamRandomPortIntegrationTest
@TestPropertySource(properties = {"mfa.passkey.enabled=true",
    "mfa.passkey.max-credentials-per-account=2"})
public class PasskeyMultiCredentialTests extends PasskeyAuthenticationTestSupport {

  public static final String TEST_USERNAME = "test";
  public static final String TEST_PASSWORD = "password";
  public static final String LABEL_A = "Key A";
  public static final String LABEL_B = "Key B";
  public static final String LABEL_C = "Key C";

  public static final String PASSKEY_REGISTERED_SUBJECT = "Passkey registered";
  public static final String PASSKEY_REMOVED_SUBJECT = "Passkey removed";

  @AfterEach
  void cleanup() {
    cleanupPasskeysAndNotifications(TEST_USERNAME);
  }

  private List<PasskeyDTO> listPasskeys(Cookie session) throws Exception {
    // @formatter:off
    String body = RestAssured.given()
        .cookie(session)
      .when()
        .get(BASE_URL)
      .then()
        .statusCode(HttpStatus.OK.value())
        .extract().asString();
    // @formatter:on
    return mapper.readValue(body, new TypeReference<List<PasskeyDTO>>() {});
  }

  private String uuidOf(Cookie session, String label) throws Exception {
    return listPasskeys(session).stream()
      .filter(p -> label.equals(p.getLabel()))
      .map(PasskeyDTO::getUuid)
      .findFirst()
      .orElseThrow();
  }

  private List<String> allowedCredentialIds(PasskeyAssertionOptionsDTO options) {
    return options.getAllowCredentials()
      .stream()
      .map(PasskeyCredentialDescriptorDTO::getId)
      .collect(Collectors.toList());
  }

  private List<String> subjectsOf(IamNotificationType type) {
    return notificationRepository.findByNotificationType(type)
      .stream()
      .map(IamEmailNotification::getSubject)
      .collect(Collectors.toList());
  }

  @Test
  void eitherPasskeyCompletesTheLoginAndARemovedOneStopsWorking() throws Exception {
    PasskeyTestAuthenticator keyA = new PasskeyTestAuthenticator(Algorithm.ES256);
    PasskeyTestAuthenticator keyB = new PasskeyTestAuthenticator(Algorithm.RS256);

    Cookie session = loginWithoutSecondFactor(TEST_USERNAME, TEST_PASSWORD);
    registrationResponse(session, keyA, false, LABEL_A).then()
      .statusCode(HttpStatus.CREATED.value())
      .body("uuid", notNullValue());
    // The second passkey is registered by the same, still fully authenticated, session
    registrationResponse(session, keyB, false, LABEL_B).then()
      .statusCode(HttpStatus.CREATED.value())
      .body("label", is(LABEL_B));
    assertThat(listPasskeys(session), hasSize(2));
    assertThat(subjectsOf(IamNotificationType.MFA_ENABLE), hasSize(2));
    assertThat(subjectsOf(IamNotificationType.MFA_ENABLE),
        hasItem(containsString(PASSKEY_REGISTERED_SUBJECT)));
    logout(session);

    // Both credentials are offered and the first one completes the login
    session = loginExpectingVerification(TEST_USERNAME, TEST_PASSWORD);
    String csrf = csrfTokenFrom(verifyPage(session));
    PasskeyAssertionOptionsDTO options = assertionOptions(session);
    assertThat(allowedCredentialIds(options), containsInAnyOrder(keyA.getCredentialIdBase64Url(),
        keyB.getCredentialIdBase64Url()));
    PasskeyAssertionDTO withA =
        assertionFor(keyA, options.getChallenge(), TEST_ORIGIN, false, 1, null);
    session = assertVerificationSucceeded(verifyWithPasskey(session, csrf, withA), session);
    logout(session);

    // The second one completes it as well
    session = loginExpectingVerification(TEST_USERNAME, TEST_PASSWORD);
    csrf = csrfTokenFrom(verifyPage(session));
    session = assertVerificationSucceeded(
        verifyWithPasskey(session, csrf, assertion(session, keyB, 1, false)), session);

    // Each credential keeps its own counter and last use
    for (IamPasskey stored : passkeyRepository.findByAccountUsername(TEST_USERNAME)) {
      assertThat(stored.getSignCount(), is(1L));
      assertThat(stored.getLastUsedTime(), notNullValue());
    }

    // The fully authenticated user removes the first passkey, proving possession of it: a removal
    // without proof is refused, and the proof is consumed with the removal
    String uuidA = uuidOf(session, LABEL_A);
    // @formatter:off
    removePasskey(session, uuidA, null).then()
      .statusCode(HttpStatus.BAD_REQUEST.value())
      .body("error", is(REMOVAL_PROOF_REQUIRED_MESSAGE));
    // @formatter:on
    PasskeyRemovalDTO proof = removalProof(session, keyA, 2);
    assertThat(removePasskey(session, uuidA, proof).getStatusCode(),
        is(HttpStatus.NO_CONTENT.value()));
    assertThat(removePasskey(session, uuidA, proof).getStatusCode(),
        is(HttpStatus.NOT_FOUND.value()));
    assertThat(listPasskeys(session), hasSize(1));
    assertThat(listPasskeys(session).get(0).getLabel(), is(LABEL_B));
    assertThat(subjectsOf(IamNotificationType.MFA_DISABLE),
        hasItem(containsString(PASSKEY_REMOVED_SUBJECT)));
    logout(session);

    // Only the surviving credential is offered: the removed one is rejected, the other works
    session = loginExpectingVerification(TEST_USERNAME, TEST_PASSWORD);
    csrf = csrfTokenFrom(verifyPage(session));
    options = assertionOptions(session);
    assertThat(allowedCredentialIds(options), is(List.of(keyB.getCredentialIdBase64Url())));
    PasskeyAssertionDTO removed =
        assertionFor(keyA, options.getChallenge(), TEST_ORIGIN, false, 2, null);
    assertVerificationFailed(verifyWithPasskey(session, csrf, removed));

    session = assertVerificationSucceeded(
        verifyWithPasskey(session, csrf, assertion(session, keyB, 2, false)), session);
    IamPasskey stored = passkeyRepository.findByAccountUsername(TEST_USERNAME).get(0);
    assertThat(stored.getLabel(), is(LABEL_B));
    assertThat(stored.getSignCount(), is(2L));
  }

  @Test
  void registrationBeyondTheLimitIsRejectedUntilAPasskeyIsRemoved() throws Exception {
    PasskeyTestAuthenticator keyA = new PasskeyTestAuthenticator(Algorithm.ES256);
    PasskeyTestAuthenticator keyB = new PasskeyTestAuthenticator(Algorithm.ES256);
    PasskeyTestAuthenticator keyC = new PasskeyTestAuthenticator(Algorithm.ES256);

    Cookie session = loginWithoutSecondFactor(TEST_USERNAME, TEST_PASSWORD);
    registrationResponse(session, keyA, false, LABEL_A).then()
      .statusCode(HttpStatus.CREATED.value());
    registrationResponse(session, keyB, false, LABEL_B).then()
      .statusCode(HttpStatus.CREATED.value());

    // The options are still issued, the registration itself is refused
    // @formatter:off
    registrationResponse(session, keyC, false, LABEL_C).then()
      .statusCode(HttpStatus.CONFLICT.value())
      .body("error", is(LIMIT_EXCEEDED_MESSAGE));
    // @formatter:on
    assertThat(listPasskeys(session), hasSize(2));
    assertThat(passkeyRepository.findByCredentialId(keyC.getCredentialIdBase64Url()).isPresent(),
        is(false));

    // Once a passkey is removed there is room for a new one, but not for a credential that is
    // already registered
    String uuidB = uuidOf(session, LABEL_B);
    assertThat(removePasskey(session, uuidB, removalProof(session, keyB, 1)).getStatusCode(),
        is(HttpStatus.NO_CONTENT.value()));
    registrationResponse(session, keyA, false, "Again").then()
      .statusCode(HttpStatus.BAD_REQUEST.value())
      .body("error", is(CREDENTIAL_ALREADY_REGISTERED_MESSAGE));
    assertThat(listPasskeys(session), hasSize(1));
    registrationResponse(session, keyC, false, LABEL_C).then()
      .statusCode(HttpStatus.CREATED.value())
      .body("label", is(LABEL_C));
    assertThat(listPasskeys(session).stream().map(PasskeyDTO::getLabel).collect(Collectors.toList()),
        containsInAnyOrder(LABEL_A, LABEL_C));
    logout(session);

    // The new passkey completes the login
    session = loginExpectingVerification(TEST_USERNAME, TEST_PASSWORD);
    String csrf = csrfTokenFrom(verifyPage(session));
    assertVerificationSucceeded(verifyWithPasskey(session, csrf, assertion(session, keyC, 1, false)),
        session);
  }

  @Test
  void aChallengeDoesNotSurviveLogout() throws Exception {
    PasskeyTestAuthenticator key = new PasskeyTestAuthenticator(Algorithm.ES256);

    Cookie session = loginWithoutSecondFactor(TEST_USERNAME, TEST_PASSWORD);
    registerPasskey(session, key);
    logout(session);

    // A challenge is issued, then the user logs out in the middle of the ceremony
    Cookie abandoned = loginExpectingVerification(TEST_USERNAME, TEST_PASSWORD);
    String abandonedCsrf = csrfTokenFrom(verifyPage(abandoned));
    String oldChallenge = assertionOptions(abandoned).getChallenge();
    logout(abandoned);

    // The assertion for the old challenge is useless in the old session...
    PasskeyAssertionDTO stale = assertionFor(key, oldChallenge, TEST_ORIGIN, false, 1, null);
    Response oldSession = verifyWithPasskey(abandoned, abandonedCsrf, stale);
    assertThat(oldSession.getHeader("Location"), not(containsString("/authorize")));

    // ...and in a new one
    session = loginExpectingVerification(TEST_USERNAME, TEST_PASSWORD);
    String csrf = csrfTokenFrom(verifyPage(session));
    assertVerificationFailed(verifyWithPasskey(session, csrf, stale));
    // The new session has not even requested a challenge yet: a valid-looking assertion for
    // whatever challenge is rejected
    PasskeyAssertionDTO unsolicited = assertionFor(key,
        PasskeyTestAuthenticator.base64Url(PasskeyTestAuthenticator.randomBytes(32)), TEST_ORIGIN,
        false, 2, null);
    assertVerificationFailed(verifyWithPasskey(session, csrf, unsolicited));

    IamPasskey stored = passkeyRepository.findByAccountUsername(TEST_USERNAME).get(0);
    assertThat(stored.getSignCount(), is(0L));
    assertThat(stored.getLastUsedTime(), nullValue());

    // A challenge issued to the new session completes the login
    assertVerificationSucceeded(verifyWithPasskey(session, csrf, assertion(session, key, 3)),
        session);
    assertThat(passkeyRepository.findByAccountUsername(TEST_USERNAME).get(0).getSignCount(),
        is(3L));
  }
}
