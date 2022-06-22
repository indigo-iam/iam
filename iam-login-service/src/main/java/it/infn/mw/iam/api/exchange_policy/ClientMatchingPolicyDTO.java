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
package it.infn.mw.iam.api.exchange_policy;

import static it.infn.mw.iam.persistence.model.IamClientMatchingPolicy.ClientMatchingPolicyType.ANY;
import static it.infn.mw.iam.persistence.model.IamClientMatchingPolicy.ClientMatchingPolicyType.BY_ID;
import static it.infn.mw.iam.persistence.model.IamClientMatchingPolicy.ClientMatchingPolicyType.BY_SCOPE;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import it.infn.mw.iam.persistence.model.IamClientMatchingPolicy.ClientMatchingPolicyType;

@JsonInclude(value = JsonInclude.Include.NON_EMPTY)
public class ClientMatchingPolicyDTO {

  @NotNull
  ClientMatchingPolicyType type;

  @Size(max = 256,
      message = "Invalid token exchange policy: the matchParam string must be at most 256 characters long")
  String matchParam;

  public ClientMatchingPolicyDTO() {
    type = ClientMatchingPolicyType.ANY;
  }
  
  @JsonCreator
  public ClientMatchingPolicyDTO(@JsonProperty("type") ClientMatchingPolicyType type,
      @JsonProperty("matchParam") String matchParam) {
    
    this.type = type;
    this.matchParam = matchParam;
  }

  public ClientMatchingPolicyType getType() {
    return type;
  }

  public void setType(ClientMatchingPolicyType type) {
    this.type = type;
  }

  public String getMatchParam() {
    return matchParam;
  }

  public void setMatchParam(String matchParam) {
    this.matchParam = matchParam;
  }
  
  public static ClientMatchingPolicyDTO anyClient() {
    ClientMatchingPolicyDTO dto = new ClientMatchingPolicyDTO();
    dto.setType(ANY);
    return dto;
  }
  
  public static ClientMatchingPolicyDTO clientById(String clientId) {
    ClientMatchingPolicyDTO dto = new ClientMatchingPolicyDTO();
    dto.setType(BY_ID);
    dto.setMatchParam(clientId);
    return dto;
  }
  
  public static ClientMatchingPolicyDTO clientByScope(String clientScope) {
    ClientMatchingPolicyDTO dto = new ClientMatchingPolicyDTO();
    dto.setType(BY_SCOPE);
    dto.setMatchParam(clientScope);
    return dto;
  }
  
}
