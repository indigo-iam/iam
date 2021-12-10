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
package it.infn.mw.iam.authn.multi_factor_authentication.authenticator_app;

import javax.validation.constraints.NotEmpty;

/**
 * DTO containing a recovery code for MFA secrets
 */
public class RecoveryCodeDTO {

  @NotEmpty(message = "Recovery code cannot be empty")
  private String recoveryCode;


  /**
   * @return the recoveryCode
   */
  public String getRecoveryCode() {
    return recoveryCode;
  }


  /**
   * @param recoveryCode new recoveryCode
   * @return nothing
   */
  public void setRecoveryCode(final String recoveryCode) {
    this.recoveryCode = recoveryCode;
  }
}
