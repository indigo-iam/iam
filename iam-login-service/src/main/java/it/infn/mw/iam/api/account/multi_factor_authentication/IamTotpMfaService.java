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
package it.infn.mw.iam.api.account.multi_factor_authentication;

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamTotpMfa;

public interface IamTotpMfaService {

  /**
   * Generates and attaches a TOTP MFA secret to a user account, along with a set of recovery codes
   * This is pre-emptive to actually enabling TOTP MFA on the account - the secret is written for
   * server-side TOTP verification during the user's enabling of MFA on their account
   * 
   * @param account the account to add the secret to
   * @return the new TOTP secret
   */
  IamTotpMfa addTotpMfaSecret(IamAccount account);

  /**
   * Adds a set of recovery codes to a given account's TOTP secret.
   * 
   * @param account the account to add recovery codes to
   * @return the affected TOTP secret
   */
  IamTotpMfa addTotpMfaRecoveryCodes(IamAccount account);

  /**
   * Enables TOTP MFA on a provided account. Relies on the account already having a non-active TOTP
   * secret attached to it
   * 
   * @param account the account to enable TOTP MFA on
   * @return the newly-enabled TOTP secret
   */
  IamTotpMfa enableTotpMfa(IamAccount account);

  /**
   * Disables TOTP MFA on a provided account. Relies on the account having an active TOTP secret
   * attached to it. Disabling means to delete the secret entirely (if a user chooses to enable
   * again, a new secret is generated anyway)
   * 
   * @param account the account to disable TOTP MFA on
   * @return the newly-disabled TOTP MFA
   */
  IamTotpMfa disableTotpMfa(IamAccount account);

  /**
   * Verifies a provided TOTP against an account multi-factor secret
   * 
   * @param account the account whose secret we will check against
   * @param totp the TOTP to validate
   * @return true if valid, false otherwise
   */
  boolean verifyTotp(IamAccount account, String totp);

  /**
   * Verifies a provided recovery code against an account
   * 
   * @param account the account we will check against
   * @param recoveryCode the recovery code to validate
   * @return true if valid, false otherwise
   */
  boolean verifyRecoveryCode(IamAccount account, String recoveryCode);
}
