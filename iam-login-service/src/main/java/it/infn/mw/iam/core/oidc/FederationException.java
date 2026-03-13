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
package it.infn.mw.iam.core.oidc;

public class FederationException extends Exception {

  public static final String INVALID_CLIENT_METADATA = "invalid_client_metadata";
  public static final String INVALID_REDIRECT_URI = "invalid_redirect_uri";
  public static final String INVALID_REQUEST = "invalid_request";
  public static final String INVALID_TRUST_CHAIN = "invalid_trust_chain";

  private static final long serialVersionUID = 1L;
  private final String errorCode;

  private FederationException(String errorCode, String message) {
    super(message);
    this.errorCode = errorCode;
  }

  private FederationException(String errorCode, String message, Throwable cause) {
    super(message, cause);
    this.errorCode = errorCode;
  }

  public String getErrorCode() {
    return errorCode;
  }

  public static FederationException invalidClientMetadata(String message) {
    return new FederationException(INVALID_CLIENT_METADATA, message);
  }

//  public static FederationException invalidClientMetadata(String message, Throwable cause) {
//    return new FederationException(INVALID_CLIENT_METADATA, message, cause);
//  }

  public static FederationException invalidRedirectUri(String message) {
    return new FederationException(INVALID_REDIRECT_URI, message);
  }

  public static FederationException invalidRedirectUri(String message, Throwable cause) {
    return new FederationException(INVALID_REDIRECT_URI, message, cause);
  }

  public static FederationException invalidRequest(String message) {
    return new FederationException(INVALID_REQUEST, message);
  }

  public static FederationException invalidRequest(String message, Throwable cause) {
    return new FederationException(INVALID_REQUEST, message, cause);
  }

  public static FederationException invalidTrustChain(String message) {
    return new FederationException(INVALID_TRUST_CHAIN, message);
  }

  public static FederationException invalidTrustChain(String message, Throwable cause) {
    return new FederationException(INVALID_TRUST_CHAIN, message, cause);
  }
}
