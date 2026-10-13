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
package it.infn.mw.iam.api.account.multi_factor_authentication.passkey;

import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.converter.AttestedCredentialDataConverter;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.AuthenticationRequest;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.validator.exception.MaliciousCounterValueException;
import com.webauthn4j.validator.exception.ValidationException;

import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.error.PasskeyCeremonyException;

/**
 * Thin wrapper around webauthn4j that performs the server side of the WebAuthn registration and
 * authentication ceremonies for a fixed Relying Party. Attestation is not verified (any
 * attestation format, including "none", is accepted) since IAM does not maintain a list of trusted
 * authenticator models
 */
public class PasskeyRelyingParty {

  public static final List<COSEAlgorithmIdentifier> SUPPORTED_ALGORITHMS =
      List.of(COSEAlgorithmIdentifier.ES256, COSEAlgorithmIdentifier.EdDSA,
          COSEAlgorithmIdentifier.RS256);

  public static final String COUNTER_REGRESSION_MESSAGE =
      "Passkey verification failed: the signature counter went backwards, "
          + "the authenticator may have been cloned";

  private final Set<Origin> origins;
  private final String rpId;
  private final String rpName;
  private final boolean userVerificationRequired;
  private final WebAuthnManager webAuthnManager;
  private final AttestedCredentialDataConverter attestedCredentialDataConverter;

  public PasskeyRelyingParty(Set<String> allowedOrigins, String rpId, String rpName,
      boolean userVerificationRequired) {
    this.origins = allowedOrigins.stream().map(Origin::new).collect(Collectors.toSet());
    this.rpId = rpId;
    this.rpName = rpName;
    this.userVerificationRequired = userVerificationRequired;
    ObjectConverter objectConverter = new ObjectConverter();
    this.webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager(objectConverter);
    this.attestedCredentialDataConverter = new AttestedCredentialDataConverter(objectConverter);
  }

  public String getRpId() {
    return rpId;
  }

  public String getRpName() {
    return rpName;
  }

  public List<Long> getSupportedAlgorithmIdentifiers() {
    return SUPPORTED_ALGORITHMS.stream()
      .map(COSEAlgorithmIdentifier::getValue)
      .collect(Collectors.toList());
  }

  /**
   * Validates the response of navigator.credentials.create() against the given challenge
   *
   * @param challenge the challenge that was handed to the browser
   * @param registration the browser response
   * @return the validated credential, ready to be persisted
   * @throws PasskeyCeremonyException if the response is malformed or fails validation
   */
  public RegistrationResult verifyRegistration(byte[] challenge,
      PasskeyRegistrationDTO registration) {

    byte[] attestationObject = decode(registration.getResponse().getAttestationObject());
    byte[] clientDataJSON = decode(registration.getResponse().getClientDataJSON());
    Set<String> transports = registration.getResponse().getTransports() == null
        ? Collections.emptySet()
        : registration.getResponse()
          .getTransports()
          .stream()
          .filter(Objects::nonNull)
          .collect(Collectors.toSet());

    RegistrationRequest request =
        new RegistrationRequest(attestationObject, clientDataJSON, null, transports);

    List<PublicKeyCredentialParameters> pubKeyCredParams = SUPPORTED_ALGORITHMS.stream()
      .map(alg -> new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, alg))
      .collect(Collectors.toList());

    RegistrationParameters parameters = new RegistrationParameters(serverProperty(challenge),
        pubKeyCredParams, userVerificationRequired, true);

    RegistrationData data;
    try {
      data = webAuthnManager.validate(request, parameters);
    } catch (DataConversionException | ValidationException e) {
      throw new PasskeyCeremonyException("Passkey registration failed: " + e.getMessage(), e);
    }

    AuthenticatorData<?> authenticatorData = data.getAttestationObject().getAuthenticatorData();
    AttestedCredentialData attestedCredentialData = authenticatorData.getAttestedCredentialData();

    if (attestedCredentialData == null) {
      throw new PasskeyCeremonyException(
          "Passkey registration failed: no attested credential data");
    }

    byte[] credentialId = attestedCredentialData.getCredentialId();

    // Compared as bytes so that a padded base64url id from a non-browser client is accepted
    if (!Arrays.equals(decode(registration.getId()), credentialId)) {
      throw new PasskeyCeremonyException(
          "Passkey registration failed: credential id mismatch");
    }

    return new RegistrationResult(encode(credentialId),
        encode(attestedCredentialDataConverter.convert(attestedCredentialData)),
        attestedCredentialData.getAaguid().getValue() == null ? null
            : attestedCredentialData.getAaguid().getValue().toString(),
        authenticatorData.getSignCount(),
        data.getTransports() == null ? Collections.emptySet()
            : data.getTransports()
              .stream()
              .map(AuthenticatorTransport::getValue)
              .collect(Collectors.toSet()));
  }

  /**
   * Validates the response of navigator.credentials.get() against the given challenge and the
   * stored credential
   *
   * @param challenge the challenge that was handed to the browser
   * @param assertion the browser response
   * @param credentialId the stored, base64url encoded credential id
   * @param attestedCredentialData the stored, base64url encoded attested credential data
   * @param storedSignCount the stored signature counter
   * @param transports the stored transport hints
   * @return the new signature counter to store
   * @throws PasskeyCeremonyException if the response is malformed or fails validation
   */
  public long verifyAssertion(byte[] challenge, PasskeyAssertionDTO assertion,
      String credentialId, String attestedCredentialData, long storedSignCount,
      List<String> transports) {

    byte[] allowedCredentialId = decode(credentialId);
    byte[] presentedCredentialId = decode(assertion.getId());
    byte[] userHandle = assertion.getResponse().getUserHandle() == null ? null
        : decode(assertion.getResponse().getUserHandle());
    byte[] authenticatorData = decode(assertion.getResponse().getAuthenticatorData());
    byte[] clientDataJSON = decode(assertion.getResponse().getClientDataJSON());
    byte[] signature = decode(assertion.getResponse().getSignature());

    AuthenticationRequest request = new AuthenticationRequest(presentedCredentialId, userHandle,
        authenticatorData, clientDataJSON, null, signature);

    AuthenticatorImpl authenticator = new AuthenticatorImpl(
        attestedCredentialDataConverter.convert(decode(attestedCredentialData)), null,
        storedSignCount,
        transports.stream().map(AuthenticatorTransport::create).collect(Collectors.toSet()));

    AuthenticationParameters parameters = new AuthenticationParameters(serverProperty(challenge),
        authenticator, List.of(allowedCredentialId), userVerificationRequired, true);

    AuthenticationData data;
    try {
      data = webAuthnManager.validate(request, parameters);
    } catch (MaliciousCounterValueException e) {
      // Kept distinct from an ordinary failure: it is the signal of a cloned authenticator
      throw new PasskeyCeremonyException(COUNTER_REGRESSION_MESSAGE, e);
    } catch (DataConversionException | ValidationException e) {
      throw new PasskeyCeremonyException("Passkey verification failed: " + e.getMessage(), e);
    }

    return data.getAuthenticatorData().getSignCount();
  }

  private ServerProperty serverProperty(byte[] challenge) {
    return new ServerProperty(origins, rpId, new DefaultChallenge(challenge), null);
  }

  public static String encode(byte[] value) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
  }

  public static byte[] decode(String value) {
    try {
      return Base64.getUrlDecoder().decode(value);
    } catch (IllegalArgumentException e) {
      throw new PasskeyCeremonyException("Invalid base64url value", e);
    }
  }

  public static class RegistrationResult {

    private final String credentialId;
    private final String attestedCredentialData;
    private final String aaguid;
    private final long signCount;
    private final Set<String> transports;

    public RegistrationResult(String credentialId, String attestedCredentialData, String aaguid,
        long signCount, Set<String> transports) {
      this.credentialId = credentialId;
      this.attestedCredentialData = attestedCredentialData;
      this.aaguid = aaguid;
      this.signCount = signCount;
      this.transports = transports;
    }

    public String getCredentialId() {
      return credentialId;
    }

    public String getAttestedCredentialData() {
      return attestedCredentialData;
    }

    public String getAaguid() {
      return aaguid;
    }

    public long getSignCount() {
      return signCount;
    }

    public Set<String> getTransports() {
      return transports;
    }
  }
}
