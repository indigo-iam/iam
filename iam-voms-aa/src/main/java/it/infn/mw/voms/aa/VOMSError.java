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
package it.infn.mw.voms.aa;

public enum VOMSError {

  NoSuchUser(1001, 403, "No such user."),
  NoSuchAttribute(1007, 400, "Cannot issue a user requested attribtue."),
  SuspendedUser(1004, 403, "The user is supended."),
  SuspendedCertificate(1001, 403, "The user certificate is suspended."),
  BadRequest(1006, 400, "Bad request."),
  InternalError(1006, 500, "Internal server error."),
  EndpointDisabled(1006, 500, "VOMS endpoint is currently not enabled."),
  UnauthenticatedClient(1006, 400, "Client is not authenticated.");

  private VOMSError(int legacyCode, int httpStatus, String message) {

    this.legacyErrorCode = legacyCode;
    this.httpStatus = httpStatus;
    this.defaultMessage = message;
  }

  private int legacyErrorCode;
  private int httpStatus;
  private String defaultMessage;

  public int getHttpStatus() {

    return httpStatus;
  }

  public int getLegacyErrorCode() {

    return legacyErrorCode;
  }

  public String getDefaultMessage() {

    return defaultMessage;
  }

}
