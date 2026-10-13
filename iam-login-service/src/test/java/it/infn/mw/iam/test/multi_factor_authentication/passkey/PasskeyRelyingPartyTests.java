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
import static it.infn.mw.iam.test.multi_factor_authentication.passkey.PasskeyTestAuthenticator.randomBytes;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyAssertionDTO;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyRegistrationDTO;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyRelyingParty;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyRelyingParty.RegistrationResult;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.error.PasskeyCeremonyException;
import it.infn.mw.iam.test.multi_factor_authentication.passkey.PasskeyTestAuthenticator.Algorithm;

class PasskeyRelyingPartyTests extends PasskeyTestSupport {

  private static final String OTHER_ORIGIN = "http://evil.example.org";

  private final PasskeyRelyingParty relyingParty =
      new PasskeyRelyingParty(Set.of(TEST_ORIGIN), TEST_RP_ID, TEST_RP_NAME, false);

  private final PasskeyRelyingParty strictRelyingParty =
      new PasskeyRelyingParty(Set.of(TEST_ORIGIN), TEST_RP_ID, TEST_RP_NAME, true);

  private static byte[] challenge() {
    return randomBytes(32);
  }

  private RegistrationResult register(PasskeyRelyingParty rp, PasskeyTestAuthenticator authenticator,
      byte[] challenge, boolean userVerified) {
    return rp.verifyRegistration(challenge,
        registrationFor(authenticator, base64Url(challenge), TEST_ORIGIN, userVerified,
            List.of("usb", "nfc")));
  }

  @Test
  void supportedAlgorithmsAreEs256EdDsaAndRs256() {
    assertEquals(List.of(-7L, -8L, -257L), relyingParty.getSupportedAlgorithmIdentifiers());
    assertEquals(TEST_RP_ID, relyingParty.getRpId());
  }

  @ParameterizedTest
  @EnumSource(Algorithm.class)
  void registrationSucceeds(Algorithm algorithm) {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(algorithm);
    byte[] challenge = challenge();

    RegistrationResult result = register(relyingParty, authenticator, challenge, false);

    assertEquals(authenticator.getCredentialIdBase64Url(), result.getCredentialId());
    assertEquals(authenticator.getAaguid().toString(), result.getAaguid());
    assertEquals(0, result.getSignCount());
    assertEquals(Set.of("usb", "nfc"), result.getTransports());
    assertThat(result.getAttestedCredentialData().length(), greaterThan(50));
  }

  @Test
  void registrationWithZeroAaguidSucceeds() {
    PasskeyTestAuthenticator authenticator =
        new PasskeyTestAuthenticator(Algorithm.ES256, randomBytes(32), new java.util.UUID(0, 0));
    byte[] challenge = challenge();

    RegistrationResult result = register(relyingParty, authenticator, challenge, false);

    assertEquals("00000000-0000-0000-0000-000000000000", result.getAaguid());
  }

  @Test
  void registrationWithWrongChallengeFails() {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    PasskeyRegistrationDTO registration =
        registrationFor(authenticator, base64Url(challenge()), TEST_ORIGIN, false, List.of());

    PasskeyCeremonyException e = assertThrows(PasskeyCeremonyException.class,
        () -> relyingParty.verifyRegistration(challenge(), registration));
    assertThat(e.getMessage(), containsString("registration failed"));
  }

  @Test
  void registrationFromWrongOriginFails() {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    byte[] challenge = challenge();
    PasskeyRegistrationDTO registration =
        registrationFor(authenticator, base64Url(challenge), OTHER_ORIGIN, false, List.of());

    assertThrows(PasskeyCeremonyException.class,
        () -> relyingParty.verifyRegistration(challenge, registration));
  }

  @Test
  void registrationWithCredentialIdMismatchFails() {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    byte[] challenge = challenge();
    PasskeyRegistrationDTO registration =
        registrationFor(authenticator, base64Url(challenge), TEST_ORIGIN, false, List.of());
    registration.setId(base64Url(randomBytes(16)));

    PasskeyCeremonyException e = assertThrows(PasskeyCeremonyException.class,
        () -> relyingParty.verifyRegistration(challenge, registration));
    assertThat(e.getMessage(), containsString("mismatch"));
  }

  @Test
  void registrationWithoutUserVerificationFailsWhenRequired() {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    byte[] challenge = challenge();
    PasskeyRegistrationDTO registration =
        registrationFor(authenticator, base64Url(challenge), TEST_ORIGIN, false, List.of());

    assertThrows(PasskeyCeremonyException.class,
        () -> strictRelyingParty.verifyRegistration(challenge, registration));

    byte[] otherChallenge = challenge();
    RegistrationResult result = register(strictRelyingParty, authenticator, otherChallenge, true);
    assertEquals(authenticator.getCredentialIdBase64Url(), result.getCredentialId());
  }

  @Test
  void registrationWithMalformedDataFails() {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    byte[] challenge = challenge();
    PasskeyRegistrationDTO notBase64 =
        registrationFor(authenticator, base64Url(challenge), TEST_ORIGIN, false, List.of());
    notBase64.getResponse().setAttestationObject("not-base64!!");

    assertThrows(PasskeyCeremonyException.class,
        () -> relyingParty.verifyRegistration(challenge, notBase64));

    PasskeyRegistrationDTO notCbor =
        registrationFor(authenticator, base64Url(challenge), TEST_ORIGIN, false, List.of());
    notCbor.getResponse().setAttestationObject(base64Url(new byte[] {1, 2, 3}));

    assertThrows(PasskeyCeremonyException.class,
        () -> relyingParty.verifyRegistration(challenge, notCbor));
  }

  @ParameterizedTest
  @EnumSource(Algorithm.class)
  void assertionSucceedsAndReturnsNewCounter(Algorithm algorithm) {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(algorithm);
    RegistrationResult registered = register(relyingParty, authenticator, challenge(), false);

    byte[] challenge = challenge();
    long counter = relyingParty.verifyAssertion(challenge,
        assertionFor(authenticator, base64Url(challenge), TEST_ORIGIN, false, 1, null),
        registered.getCredentialId(), registered.getAttestedCredentialData(), 0,
        List.of("usb", "nfc"));
    assertEquals(1, counter);

    byte[] otherChallenge = challenge();
    counter = relyingParty.verifyAssertion(otherChallenge,
        assertionFor(authenticator, base64Url(otherChallenge), TEST_ORIGIN, false, 5,
            base64Url("user-handle".getBytes())),
        registered.getCredentialId(), registered.getAttestedCredentialData(), 1, List.of());
    assertEquals(5, counter);
  }

  @Test
  void assertionWithZeroCountersSucceeds() {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    RegistrationResult registered = register(relyingParty, authenticator, challenge(), false);
    byte[] challenge = challenge();

    long counter = relyingParty.verifyAssertion(challenge,
        assertionFor(authenticator, base64Url(challenge), TEST_ORIGIN, false, 0, null),
        registered.getCredentialId(), registered.getAttestedCredentialData(), 0, List.of());
    assertEquals(0, counter);
  }

  @Test
  void assertionWithNonIncreasingCounterFails() {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    RegistrationResult registered = register(relyingParty, authenticator, challenge(), false);
    byte[] challenge = challenge();
    PasskeyAssertionDTO assertion =
        assertionFor(authenticator, base64Url(challenge), TEST_ORIGIN, false, 5, null);

    PasskeyCeremonyException e = assertThrows(PasskeyCeremonyException.class,
        () -> relyingParty.verifyAssertion(challenge, assertion, registered.getCredentialId(),
            registered.getAttestedCredentialData(), 5, List.of()));
    assertThat(e.getMessage(), containsString("counter"));
  }

  @Test
  void assertionWithWrongChallengeFails() {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    RegistrationResult registered = register(relyingParty, authenticator, challenge(), false);
    PasskeyAssertionDTO assertion =
        assertionFor(authenticator, base64Url(challenge()), TEST_ORIGIN, false, 10, null);

    assertThrows(PasskeyCeremonyException.class,
        () -> relyingParty.verifyAssertion(challenge(), assertion, registered.getCredentialId(),
            registered.getAttestedCredentialData(), 0, List.of()));
  }

  @Test
  void assertionFromWrongOriginFails() {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    RegistrationResult registered = register(relyingParty, authenticator, challenge(), false);
    byte[] challenge = challenge();
    PasskeyAssertionDTO assertion =
        assertionFor(authenticator, base64Url(challenge), OTHER_ORIGIN, false, 10, null);

    assertThrows(PasskeyCeremonyException.class,
        () -> relyingParty.verifyAssertion(challenge, assertion, registered.getCredentialId(),
            registered.getAttestedCredentialData(), 0, List.of()));
  }

  @Test
  void assertionWithTamperedSignatureFails() {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    RegistrationResult registered = register(relyingParty, authenticator, challenge(), false);
    byte[] challenge = challenge();
    PasskeyAssertionDTO assertion =
        assertionFor(authenticator, base64Url(challenge), TEST_ORIGIN, false, 10, null);
    byte[] signature = PasskeyRelyingParty.decode(assertion.getResponse().getSignature());
    signature[signature.length - 1] ^= 0x55;
    assertion.getResponse().setSignature(base64Url(signature));

    assertThrows(PasskeyCeremonyException.class,
        () -> relyingParty.verifyAssertion(challenge, assertion, registered.getCredentialId(),
            registered.getAttestedCredentialData(), 0, List.of()));
  }

  @Test
  void assertionSignedByAnotherKeyFails() {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    RegistrationResult registered = register(relyingParty, authenticator, challenge(), false);
    PasskeyTestAuthenticator other = new PasskeyTestAuthenticator(Algorithm.ES256,
        authenticator.getCredentialId(), authenticator.getAaguid());
    byte[] challenge = challenge();
    PasskeyAssertionDTO assertion =
        assertionFor(other, base64Url(challenge), TEST_ORIGIN, false, 10, null);

    assertThrows(PasskeyCeremonyException.class,
        () -> relyingParty.verifyAssertion(challenge, assertion, registered.getCredentialId(),
            registered.getAttestedCredentialData(), 0, List.of()));
  }

  @Test
  void assertionForAnotherCredentialFails() {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    RegistrationResult registered = register(relyingParty, authenticator, challenge(), false);
    byte[] challenge = challenge();
    PasskeyAssertionDTO assertion =
        assertionFor(authenticator, base64Url(challenge), TEST_ORIGIN, false, 10, null);
    assertion.setId(base64Url(randomBytes(16)));

    assertThrows(PasskeyCeremonyException.class,
        () -> relyingParty.verifyAssertion(challenge, assertion, registered.getCredentialId(),
            registered.getAttestedCredentialData(), 0, List.of()));
  }

  @Test
  void assertionWithoutUserVerificationFailsWhenRequired() {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    RegistrationResult registered = register(strictRelyingParty, authenticator, challenge(), true);
    byte[] challenge = challenge();
    PasskeyAssertionDTO assertion =
        assertionFor(authenticator, base64Url(challenge), TEST_ORIGIN, false, 10, null);

    assertThrows(PasskeyCeremonyException.class,
        () -> strictRelyingParty.verifyAssertion(challenge, assertion,
            registered.getCredentialId(), registered.getAttestedCredentialData(), 0, List.of()));

    byte[] otherChallenge = challenge();
    long counter = strictRelyingParty.verifyAssertion(otherChallenge,
        assertionFor(authenticator, base64Url(otherChallenge), TEST_ORIGIN, true, 11, null),
        registered.getCredentialId(), registered.getAttestedCredentialData(), 0, List.of());
    assertEquals(11, counter);
  }

  @Test
  void assertionFromAdditionalAllowedOriginSucceeds() {
    PasskeyRelyingParty multiOrigin = new PasskeyRelyingParty(
        Set.of(TEST_ORIGIN, "http://localhost:8443"), TEST_RP_ID, TEST_RP_NAME, false);
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    RegistrationResult registered = register(multiOrigin, authenticator, challenge(), false);
    byte[] challenge = challenge();

    long counter = multiOrigin.verifyAssertion(challenge,
        assertionFor(authenticator, base64Url(challenge), "http://localhost:8443", false, 20,
            null),
        registered.getCredentialId(), registered.getAttestedCredentialData(), 0, List.of());
    assertEquals(20, counter);
  }

  @Test
  void decodeRejectsInvalidBase64Url() {
    assertThrows(PasskeyCeremonyException.class, () -> PasskeyRelyingParty.decode("***"));
  }
}
