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
package it.infn.mw.iam.api.account.multi_factor_authentication.passkey;

import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * The PublicKeyCredential returned by navigator.credentials.get(), serialised with base64url
 * binary fields
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class PasskeyAssertionDTO {

  @JsonIgnoreProperties(ignoreUnknown = true)
  public static class Response {

    @NotBlank
    private String clientDataJSON;

    @NotBlank
    private String authenticatorData;

    @NotBlank
    private String signature;

    private String userHandle;

    public String getClientDataJSON() {
      return clientDataJSON;
    }

    public void setClientDataJSON(String clientDataJSON) {
      this.clientDataJSON = clientDataJSON;
    }

    public String getAuthenticatorData() {
      return authenticatorData;
    }

    public void setAuthenticatorData(String authenticatorData) {
      this.authenticatorData = authenticatorData;
    }

    public String getSignature() {
      return signature;
    }

    public void setSignature(String signature) {
      this.signature = signature;
    }

    public String getUserHandle() {
      return userHandle;
    }

    public void setUserHandle(String userHandle) {
      this.userHandle = userHandle;
    }
  }

  @NotBlank
  private String id;

  private String rawId;

  private String type;

  @NotNull
  @Valid
  private Response response;

  public String getId() {
    return id;
  }

  public void setId(String id) {
    this.id = id;
  }

  public String getRawId() {
    return rawId;
  }

  public void setRawId(String rawId) {
    this.rawId = rawId;
  }

  public String getType() {
    return type;
  }

  public void setType(String type) {
    this.type = type;
  }

  public Response getResponse() {
    return response;
  }

  public void setResponse(Response response) {
    this.response = response;
  }
}
