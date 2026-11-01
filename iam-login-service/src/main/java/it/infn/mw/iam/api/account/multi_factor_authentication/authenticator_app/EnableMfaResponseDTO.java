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

/**
 * DTO returned once authenticator app MFA has been enabled, telling the client where to send the
 * browser next.
 */
public class EnableMfaResponseDTO {

  private String redirectUrl;

  public EnableMfaResponseDTO(final String redirectUrl) {
    this.redirectUrl = redirectUrl;
  }

  /**
   * @return the URL the client should navigate to
   */
  public String getRedirectUrl() {
    return redirectUrl;
  }

  /**
   * @param redirectUrl the new redirect URL
   */
  public void setRedirectUrl(final String redirectUrl) {
    this.redirectUrl = redirectUrl;
  }
}
