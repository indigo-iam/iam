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

import java.util.List;

import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyChallenge.Purpose;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamPasskey;

public interface IamPasskeyService {

  /**
   * Tells whether the passkey feature is enabled in this IAM instance
   *
   * @return true if passkeys can be registered and used
   */
  boolean isEnabled();

  /**
   * Tells whether the account has at least one passkey registered and can therefore complete MFA
   * with it. Always false when the feature is disabled
   *
   * @param account
   * @return true if the account can authenticate with a passkey
   */
  boolean isPasskeyActive(IamAccount account);

  /**
   * Returns the passkeys registered on the account
   *
   * @param account
   * @return the list of passkeys, possibly empty
   */
  List<IamPasskey> getPasskeys(IamAccount account);

  /**
   * Creates a fresh single-use challenge for a ceremony. The caller is responsible for keeping the
   * challenge in the user session and handing it back when the ceremony completes
   *
   * @param account the account the challenge is issued for
   * @param purpose the ceremony the challenge is issued for
   * @return the challenge
   */
  PasskeyChallenge createChallenge(IamAccount account, Purpose purpose);

  /**
   * Builds the options for navigator.credentials.create()
   *
   * @param account
   * @param challenge a challenge created for registration
   * @return the creation options
   */
  PasskeyRegistrationOptionsDTO getRegistrationOptions(IamAccount account,
      PasskeyChallenge challenge);

  /**
   * Verifies the response of navigator.credentials.create() and registers the new passkey
   *
   * @param account
   * @param challenge the challenge issued for this registration, or null if none was issued
   * @param registration the browser response
   * @return the new passkey
   */
  IamPasskey registerPasskey(IamAccount account, PasskeyChallenge challenge,
      PasskeyRegistrationDTO registration);

  /**
   * Builds the options for navigator.credentials.get(), listing every passkey of the account. The
   * ceremony the assertion will be accepted for is fixed by the purpose of the challenge
   *
   * @param account
   * @param challenge a challenge created for authentication or for removal
   * @return the request options
   */
  PasskeyAssertionOptionsDTO getAssertionOptions(IamAccount account, PasskeyChallenge challenge);

  /**
   * Verifies the response of navigator.credentials.get() against one of the account passkeys and
   * updates its signature counter
   *
   * @param account
   * @param challenge the challenge issued for this authentication, or null if none was issued
   * @param assertion the browser response
   * @return the passkey that was used
   */
  IamPasskey verifyPasskey(IamAccount account, PasskeyChallenge challenge,
      PasskeyAssertionDTO assertion);

  /**
   * Removes one passkey from the account, after checking that the removal is allowed by the
   * multi-factor policy and that the caller proves possession of a second factor: an assertion
   * produced with any passkey of the account against a challenge issued for removal, or a code of
   * the authenticator app when one is active. The proof is not required while the feature is
   * disabled, since stored passkeys are not accepted at login then
   *
   * @param account
   * @param passkeyUuid the passkey identifier
   * @param challenge the challenge issued for this removal, or null if none was issued
   * @param proof the proof of possession, or null if none was given
   * @return the removed passkey
   */
  IamPasskey removePasskey(IamAccount account, String passkeyUuid, PasskeyChallenge challenge,
      PasskeyRemovalDTO proof);

  /**
   * Removes every passkey from the account
   *
   * @param account
   * @return the removed passkeys, possibly empty
   */
  List<IamPasskey> removeAllPasskeys(IamAccount account);
}
