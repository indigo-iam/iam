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

import javax.validation.constraints.NotEmpty;

/**
 * DTO containing an MFA secret and QR code data URI
 */
public class SecretAndDataUriDTO {

  @NotEmpty(message = "Secret cannot be empty")
  private String secret;

  private String dataUri;

  public SecretAndDataUriDTO(final String secret) {
    this.secret = secret;
  }


  /**
   * @return the MFA secret
   */
  public String getSecret() {
    return secret;
  }


  /**
   * @param secret the new secret
   */
  public void setSecret(final String secret) {
    this.secret = secret;
  }


  /**
   * @return the QR code data URI
   */
  public String getDataUri() {
    return dataUri;
  }


  /**
   * @param dataUri the new QR code data URI
   */
  public void setDataUri(final String dataUri) {
    this.dataUri = dataUri;
  }
}
