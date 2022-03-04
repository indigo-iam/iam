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
   * Adds a TOTP secret to an account
   * 
   * @param account the account to add the secret to
   * @return the added secret
   */
  IamTotpMfa addTotpMfaSecret(IamAccount account);

  /**
   * Adds recovery codes to a TOTP secret
   * 
   * @param account the account who's TOTP secret we will add recovery codes to
   * @return the affected TOTP secret
   */
  IamTotpMfa addTotpMfaRecoveryCodes(IamAccount account);

  /**
   * Enable TOTP MFA on account with TOTP secret
   * 
   * @param account the account to enable TOTP MFA on
   * @return the enabled secret
   */
  IamTotpMfa enableTotpMfa(IamAccount account);

  /**
   * Disable TOTP MFA on account with TOTP secret
   * 
   * @param account the account to disable TOTP MFA on
   * @return the disabled secret
   */
  IamTotpMfa disableTotpMfa(IamAccount account);
}
