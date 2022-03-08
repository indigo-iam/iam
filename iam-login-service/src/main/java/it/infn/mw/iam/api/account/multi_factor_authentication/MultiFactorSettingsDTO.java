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

import javax.validation.constraints.NotEmpty;

import com.nimbusds.jose.shaded.json.JSONObject;

/**
 * DTO containing info about enabled factors of authentication
 */
public class MultiFactorSettingsDTO {

  @NotEmpty
  private boolean authenticatorAppActive;

  // add further factors if/when implemented

  public MultiFactorSettingsDTO() {}

  public MultiFactorSettingsDTO(final boolean authenticatorAppActive) {
    this.authenticatorAppActive = authenticatorAppActive;
  }


  /**
   * @return true if authenticator app is active
   */
  public boolean getAuthenticatorAppActive() {
    return authenticatorAppActive;
  }


  /**
   * @param authenticatorAppActive new status of authenticator app
   */
  public void setAuthenticatorAppActive(final boolean authenticatorAppActive) {
    this.authenticatorAppActive = authenticatorAppActive;
  }

  public JSONObject toJson() {
    JSONObject json = new JSONObject();
    json.put("authenticatorAppActive", authenticatorAppActive);
    return json;
  }
}
