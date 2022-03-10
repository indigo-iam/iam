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
package it.infn.mw.iam.api.account.multi_factor_authentication.authenticator_app;

import javax.validation.constraints.Min;
import javax.validation.constraints.NotEmpty;

import org.hibernate.validator.constraints.Length;

/**
 * DTO containing a TOTP for MFA secrets
 */
public class TotpDTO {

  @NotEmpty(message = "Totp cannot be empty")
  @Length(min = 6, max = 6, message = "Totp must be six characters in length")
  @Min(value = 0L, message = "Totp must be a numerical value")
  private String totp;


  /**
   * @return the code
   */
  public String getCode() {
    return totp;
  }


  /**
   * @param totp new code
   */
  public void setTotp(final String totp) {
    this.totp = totp;
  }
}
