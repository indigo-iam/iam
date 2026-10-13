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

import java.util.List;

import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * The PublicKeyCredential returned by navigator.credentials.create(), serialised with base64url
 * binary fields, plus the label the user chose for the new passkey
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class PasskeyRegistrationDTO {

  @JsonIgnoreProperties(ignoreUnknown = true)
  public static class Response {

    @NotBlank
    private String clientDataJSON;

    @NotBlank
    private String attestationObject;

    private List<String> transports;

    public String getClientDataJSON() {
      return clientDataJSON;
    }

    public void setClientDataJSON(String clientDataJSON) {
      this.clientDataJSON = clientDataJSON;
    }

    public String getAttestationObject() {
      return attestationObject;
    }

    public void setAttestationObject(String attestationObject) {
      this.attestationObject = attestationObject;
    }

    public List<String> getTransports() {
      return transports;
    }

    public void setTransports(List<String> transports) {
      this.transports = transports;
    }
  }

  @NotBlank
  @Size(max = 128)
  private String label;

  @NotBlank
  @Size(max = 1400)
  private String id;

  @Size(max = 1400)
  private String rawId;

  private String type;

  @NotNull
  @Valid
  private Response response;

  public String getLabel() {
    return label;
  }

  public void setLabel(String label) {
    this.label = label;
  }

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
