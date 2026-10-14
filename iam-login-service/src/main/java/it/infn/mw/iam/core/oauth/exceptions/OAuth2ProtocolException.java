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
package it.infn.mw.iam.core.oauth.exceptions;

import org.springframework.http.HttpStatus;

import it.infn.mw.iam.core.oauth.model.OAuth2ErrorCode;

public class OAuth2ProtocolException extends RuntimeException {

  private static final long serialVersionUID = 1L;

  private final HttpStatus status;
  private final OAuth2ErrorCode error;
  private final String errorDescription;

  public OAuth2ProtocolException(HttpStatus status, OAuth2ErrorCode error,
      String errorDescription) {
    super();
    this.status = status;
    this.error = error;
    this.errorDescription = errorDescription;
  }

  public HttpStatus getStatus() {
    return status;
  }

  public OAuth2ErrorCode getError() {
    return error;
  }

  public String getErrorDescription() {
    return errorDescription;
  }

  public static OAuth2ProtocolException serverError(String errorDescription) {
    return new OAuth2ProtocolException(HttpStatus.INTERNAL_SERVER_ERROR,
        OAuth2ErrorCode.SERVER_ERROR, errorDescription);
  }

  public static OAuth2ProtocolException invalidClient(String errorDescription) {
    return new OAuth2ProtocolException(HttpStatus.UNAUTHORIZED, OAuth2ErrorCode.INVALID_CLIENT,
        errorDescription);
  }

  public static OAuth2ProtocolException invalidRequest(String errorDescription) {
    return new OAuth2ProtocolException(HttpStatus.BAD_REQUEST, OAuth2ErrorCode.INVALID_REQUEST,
        errorDescription);
  }

  public static OAuth2ProtocolException invalidScope(String errorDescription) {
    return new OAuth2ProtocolException(HttpStatus.BAD_REQUEST, OAuth2ErrorCode.INVALID_SCOPE,
        errorDescription);
  }
}
