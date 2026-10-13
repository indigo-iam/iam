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
import static it.infn.mw.iam.test.multi_factor_authentication.passkey.PasskeyTestAuthenticator.clientDataJSON;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyAssertionDTO;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyRegistrationDTO;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyRelyingParty;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyRelyingParty.RegistrationResult;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamPasskey;
import it.infn.mw.iam.test.multi_factor_authentication.passkey.PasskeyTestAuthenticator.Assertion;

public class PasskeyTestSupport {

  public static final String TEST_RP_ID = "localhost";
  public static final String TEST_RP_NAME = "indigo-dc";
  public static final String TEST_ORIGIN = "http://localhost:8080";
  public static final String TEST_LABEL = "Test passkey";
  public static final String PUBLIC_KEY_TYPE = "public-key";
  public static final String CREATE_TYPE = "webauthn.create";
  public static final String GET_TYPE = "webauthn.get";

  /**
   * A passkey row with placeholder credential data: enough to make the account "passkey active"
   * in tests that do not run a WebAuthn ceremony
   */
  public static IamPasskey placeholderPasskey(IamAccount account, Instant now) {
    IamPasskey passkey = new IamPasskey(now, account);
    passkey.setUuid(UUID.randomUUID().toString());
    passkey.setLabel(TEST_LABEL);
    passkey.setCredentialId(base64Url(PasskeyTestAuthenticator.randomBytes(32)));
    passkey.setAttestedCredentialData("placeholder");
    return passkey;
  }

  /**
   * A passkey row holding the credential of the given test authenticator, as the registration
   * ceremony would have stored it: the authenticator can then sign assertions for it
   */
  public static IamPasskey registeredPasskey(IamAccount account,
      PasskeyTestAuthenticator authenticator, Instant now) {
    PasskeyRelyingParty relyingParty =
        new PasskeyRelyingParty(Set.of(TEST_ORIGIN), TEST_RP_ID, TEST_RP_NAME, false);
    byte[] challenge = PasskeyTestAuthenticator.randomBytes(32);
    RegistrationResult result = relyingParty.verifyRegistration(challenge,
        registrationFor(authenticator, base64Url(challenge), TEST_ORIGIN, false, List.of("usb")));
    IamPasskey passkey = new IamPasskey(now, account);
    passkey.setUuid(UUID.randomUUID().toString());
    passkey.setLabel(TEST_LABEL);
    passkey.setCredentialId(result.getCredentialId());
    passkey.setAttestedCredentialData(result.getAttestedCredentialData());
    passkey.setAaguid(result.getAaguid());
    passkey.setSignCount(result.getSignCount());
    passkey.setTransports("usb");
    return passkey;
  }

  public static PasskeyRegistrationDTO registrationFor(PasskeyTestAuthenticator authenticator,
      String challenge, String origin, boolean userVerified, List<String> transports) {
    return registrationFor(authenticator, challenge, origin, userVerified, transports, TEST_LABEL);
  }

  public static PasskeyRegistrationDTO registrationFor(PasskeyTestAuthenticator authenticator,
      String challenge, String origin, boolean userVerified, List<String> transports,
      String label) {
    PasskeyRegistrationDTO dto = new PasskeyRegistrationDTO();
    dto.setLabel(label);
    dto.setId(authenticator.getCredentialIdBase64Url());
    dto.setRawId(authenticator.getCredentialIdBase64Url());
    dto.setType(PUBLIC_KEY_TYPE);
    PasskeyRegistrationDTO.Response response = new PasskeyRegistrationDTO.Response();
    response.setClientDataJSON(base64Url(clientDataJSON(CREATE_TYPE, challenge, origin)));
    response.setAttestationObject(
        base64Url(authenticator.attestationObject(TEST_RP_ID, userVerified)));
    response.setTransports(transports);
    dto.setResponse(response);
    return dto;
  }

  public static PasskeyAssertionDTO assertionFor(PasskeyTestAuthenticator authenticator,
      String challenge, String origin, boolean userVerified, long signCount, String userHandle) {
    return assertionFor(authenticator, TEST_RP_ID, GET_TYPE, challenge, origin, userVerified,
        signCount, userHandle);
  }

  /**
   * An assertion whose Relying Party id and client data type are chosen by the caller, so that
   * tampered responses can be produced as well as valid ones
   */
  public static PasskeyAssertionDTO assertionFor(PasskeyTestAuthenticator authenticator,
      String rpId, String type, String challenge, String origin, boolean userVerified,
      long signCount, String userHandle) {
    byte[] clientData = clientDataJSON(type, challenge, origin);
    Assertion assertion = authenticator.sign(rpId, clientData, userVerified, signCount);
    PasskeyAssertionDTO dto = new PasskeyAssertionDTO();
    dto.setId(authenticator.getCredentialIdBase64Url());
    dto.setRawId(authenticator.getCredentialIdBase64Url());
    dto.setType(PUBLIC_KEY_TYPE);
    PasskeyAssertionDTO.Response response = new PasskeyAssertionDTO.Response();
    response.setClientDataJSON(base64Url(clientData));
    response.setAuthenticatorData(base64Url(assertion.getAuthenticatorData()));
    response.setSignature(base64Url(assertion.getSignature()));
    response.setUserHandle(userHandle);
    dto.setResponse(response);
    return dto;
  }
}
