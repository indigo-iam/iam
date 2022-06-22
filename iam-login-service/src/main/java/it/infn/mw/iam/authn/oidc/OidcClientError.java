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
package it.infn.mw.iam.authn.oidc;

import org.springframework.security.authentication.AuthenticationServiceException;

public class OidcClientError extends AuthenticationServiceException {

  /**
   * 
   */
  private static final long serialVersionUID = 1L;

  private final String error;
  private final String errorDescription;
  private final String errorUri;

  public OidcClientError(String message, Throwable cause) {
    super(message, cause);
    error = null;
    errorDescription = null;
    errorUri = null;
  }

  public OidcClientError(String message, String error, String errorDescription, String errorUri) {
    super(message);
    this.error = error;
    this.errorDescription = errorDescription;
    this.errorUri = errorUri;

  }

  public String getError() {

    return error;
  }

  public String getErrorDescription() {

    return errorDescription;
  }

  public String getErrorUri() {

    return errorUri;
  }

}
