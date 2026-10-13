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

import javax.validation.Valid;
import javax.validation.constraints.Size;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * The proof of possession of a second factor that accompanies the removal of a passkey: either an
 * assertion produced with one of the registered passkeys, or a code of the authenticator app when
 * one is active on the account
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class PasskeyRemovalDTO {

  @Valid
  private PasskeyAssertionDTO assertion;

  @Size(max = 16)
  private String totp;

  public PasskeyAssertionDTO getAssertion() {
    return assertion;
  }

  public void setAssertion(PasskeyAssertionDTO assertion) {
    this.assertion = assertion;
  }

  public String getTotp() {
    return totp;
  }

  public void setTotp(String totp) {
    this.totp = totp;
  }

  public boolean hasAssertion() {
    return assertion != null;
  }

  public boolean hasTotp() {
    return totp != null && !totp.isBlank();
  }
}
