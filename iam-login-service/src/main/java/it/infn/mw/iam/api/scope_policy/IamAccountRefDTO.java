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
package it.infn.mw.iam.api.scope_policy;

import javax.validation.constraints.Size;

import javax.validation.constraints.NotEmpty;

import it.infn.mw.iam.api.scope_policy.validation.IamAccountId;

public class IamAccountRefDTO {

  @NotEmpty(message="Invalid scope policy: the account uuid must be a valid UUID")
  @IamAccountId(message="Invalid scope policy: no IAM account found for the given UUID")
  @Size(max=36, message="Invalid scope policy: the UUID is at most 36 chars long")
  String uuid;
  
  String username;
  String location;

  public IamAccountRefDTO() {
    // empty
  }

  public String getUuid() {
    return uuid;
  }

  public void setUuid(String uuid) {
    this.uuid = uuid;
  }

  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public String getLocation() {
    return location;
  }

  public void setLocation(String location) {
    this.location = location;
  }
}
