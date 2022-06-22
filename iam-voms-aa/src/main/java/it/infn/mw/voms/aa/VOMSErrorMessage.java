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

import static java.lang.String.format;

public class VOMSErrorMessage {

  private final VOMSError error;
  private String message;

  private VOMSErrorMessage(VOMSError e, String message) {

    this.error = e;
    this.message = message;
  }

  private VOMSErrorMessage(VOMSError e) {

    this(e, null);
  }

  public String getMessage() {

    if (message == null)
      return error.getDefaultMessage();

    return message;
  }

  public void setMessage(String message) {

    this.message = message;
  }

  public VOMSError getError() {

    return error;
  }

  @Override
  public String toString() {

    return String.format("[%s] %s", error.name(),
        (message == null) ? error.getDefaultMessage() : message);
  }

  public static VOMSErrorMessage noSuchUser(String userDN, String userCA) {

    VOMSErrorMessage m = new VOMSErrorMessage(VOMSError.NoSuchUser);
    m.setMessage(String.format("User unknown to this VO: '%s' (issued by '%s')", userDN, userCA));
    return m;
  }

  public static VOMSErrorMessage noSuchAttribute(String fqan) {

    VOMSErrorMessage m = new VOMSErrorMessage(VOMSError.NoSuchAttribute);
    m.setMessage(format(
        "User is not authorized to request attribute '%s' or attribute does not exist.", fqan));
    return m;
  }

  public static VOMSErrorMessage suspendedUser(String userDN, String userCA) {

    VOMSErrorMessage m = new VOMSErrorMessage(VOMSError.SuspendedUser);
    m.setMessage(format("User '%s, %s' is not active.", userDN, userCA));
    return m;
  }

  public static VOMSErrorMessage internalError(String message) {

    VOMSErrorMessage m = new VOMSErrorMessage(VOMSError.InternalError);
    m.setMessage(message);
    return m;
  }

  public static VOMSErrorMessage endpointDisabled() {
    return new VOMSErrorMessage(VOMSError.EndpointDisabled);
  }

  public static VOMSErrorMessage unauthenticatedClient() {
    return new VOMSErrorMessage(VOMSError.UnauthenticatedClient);
  }

  public static VOMSErrorMessage badRequest(String message) {
    VOMSErrorMessage m = new VOMSErrorMessage(VOMSError.BadRequest);
    m.setMessage(message);
    return m;
  }
}
