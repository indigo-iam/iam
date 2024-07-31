
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
import javax.validation.constraints.Size;

import static it.infn.mw.iam.util.RegexUtil.PASSWORD_REGEX;
import static it.infn.mw.iam.util.RegexUtil.PASSWORD_REGEX_MESSAGE_ERROR;

public class ResetPasswordDTO {

  @NotEmpty
  @Pattern(regexp = PASSWORD_REGEX, message = PASSWORD_REGEX_MESSAGE_ERROR)
  private String updatedPassword;

  @NotEmpty
  @Size(max = 36, min = 36)
  private String token;

  public String getToken() {
    return token;
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
