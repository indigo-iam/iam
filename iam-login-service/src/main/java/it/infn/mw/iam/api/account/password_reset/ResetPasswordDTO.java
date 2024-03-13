
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
package it.infn.mw.iam.api.account.password_reset;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.Pattern;

import static it.infn.mw.iam.util.RegexUtil.PASSWORD_REGEX;;

public class ResetPasswordDTO {

  @NotEmpty
  @Pattern(regexp = PASSWORD_REGEX, message = "The password must include at least one uppercase letter, one lowercase letter, one number one symbol (e.g., @$!%*?&) and must contain at least 8 characters for greater security.")
  private String updatedPassword;

  @NotEmpty
  private String token;

  public String getToken() {
    return this.token;
  }

  public void setToken(String token) {
    this.token = token;
  }

  public String getUpdatedPassword() {
    return updatedPassword;
  }

  public void setUpdatedPassword(String updatedPassword) {
    this.updatedPassword = updatedPassword;
  }
}
