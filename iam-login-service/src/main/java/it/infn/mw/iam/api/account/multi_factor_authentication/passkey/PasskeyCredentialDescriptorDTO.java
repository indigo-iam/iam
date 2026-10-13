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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

/**
 * A PublicKeyCredentialDescriptor, used in the excludeCredentials and allowCredentials lists
 */
@JsonInclude(Include.NON_EMPTY)
public class PasskeyCredentialDescriptorDTO {

  public static final String PUBLIC_KEY_TYPE = "public-key";

  private String type = PUBLIC_KEY_TYPE;
  private String id;
  private List<String> transports;

  public PasskeyCredentialDescriptorDTO() {
    // empty constructor
  }

  public PasskeyCredentialDescriptorDTO(String id, List<String> transports) {
    this.id = id;
    this.transports = transports;
  }

  public String getType() {
    return type;
  }

  public void setType(String type) {
    this.type = type;
  }

  public String getId() {
    return id;
  }

  public void setId(String id) {
    this.id = id;
  }

  public List<String> getTransports() {
    return transports;
  }

  public void setTransports(List<String> transports) {
    this.transports = transports;
  }
}
