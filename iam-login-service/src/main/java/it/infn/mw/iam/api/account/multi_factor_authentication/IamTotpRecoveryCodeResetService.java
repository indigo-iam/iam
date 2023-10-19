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

public interface IamTotpRecoveryCodeResetService {

  /**
   * Regenerates the recovery codes attached to a provided MFA-enabled IAM account
   * 
   * @param account - the account to regenerate codes on
   */
  public IamAccount resetRecoveryCodes(IamAccount account);
}
