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

import java.util.Date;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

import it.infn.mw.iam.persistence.model.IamPasskey;

@JsonInclude(Include.NON_NULL)
public class PasskeyDTO {

  private String uuid;
  private String label;
  private String aaguid;
  private List<String> transports;
  private Date creationTime;
  private Date lastUsedTime;

  public PasskeyDTO() {
    // empty constructor
  }

  public static PasskeyDTO from(IamPasskey passkey) {
    PasskeyDTO dto = new PasskeyDTO();
    dto.setUuid(passkey.getUuid());
    dto.setLabel(passkey.getLabel());
    dto.setAaguid(passkey.getAaguid());
    dto.setTransports(PasskeyTransports.toList(passkey.getTransports()));
    dto.setCreationTime(passkey.getCreationTime());
    dto.setLastUsedTime(passkey.getLastUsedTime());
    return dto;
  }

  public String getUuid() {
    return uuid;
  }

  public void setUuid(String uuid) {
    this.uuid = uuid;
  }

  public String getLabel() {
    return label;
  }

  public void setLabel(String label) {
    this.label = label;
  }

  public String getAaguid() {
    return aaguid;
  }

  public void setAaguid(String aaguid) {
    this.aaguid = aaguid;
  }

  public List<String> getTransports() {
    return transports;
  }

  public void setTransports(List<String> transports) {
    this.transports = transports;
  }

  public Date getCreationTime() {
    return creationTime;
  }

  public void setCreationTime(Date creationTime) {
    this.creationTime = creationTime;
  }

  public Date getLastUsedTime() {
    return lastUsedTime;
  }

  public void setLastUsedTime(Date lastUsedTime) {
    this.lastUsedTime = lastUsedTime;
  }
}
