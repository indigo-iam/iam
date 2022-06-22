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

import java.util.Date;
import java.util.List;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.google.common.collect.Lists;

import it.infn.mw.iam.api.scim.controller.utils.JsonDateSerializer;
import it.infn.mw.iam.persistence.model.PolicyRule;

@JsonInclude(value = JsonInclude.Include.NON_EMPTY)
public class ExchangePolicyDTO {

  private Long id;

  @Size(max = 512,
      message = "Invalid token exchange policy: the description string must be at most 512 characters long")
  private String description;

  @JsonSerialize(using = JsonDateSerializer.class)
  private Date creationTime;

  @JsonSerialize(using = JsonDateSerializer.class)
  private Date lastUpdateTime;

  PolicyRule rule;

  @Valid
  @NotNull(message = "Invalid token exchange policy: null origin client matching policy")
  private ClientMatchingPolicyDTO originClient;

  @Valid
  @NotNull(message = "Invalid token exchange policy: null destination client matching policy")
  private ClientMatchingPolicyDTO destinationClient;

  @Valid
  private List<ExchangeScopePolicyDTO> scopePolicies = Lists.newArrayList();
  
  public ExchangePolicyDTO() {
    // empty on purpose
  }

  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public String getDescription() {
    return description;
  }

  public void setDescription(String description) {
    this.description = description;
  }

  public Date getCreationTime() {
    return creationTime;
  }

  public void setCreationTime(Date creationTime) {
    this.creationTime = creationTime;
  }

  public Date getLastUpdateTime() {
    return lastUpdateTime;
  }

  public void setLastUpdateTime(Date lastUpdateTime) {
    this.lastUpdateTime = lastUpdateTime;
  }

  public PolicyRule getRule() {
    return rule;
  }

  public void setRule(PolicyRule rule) {
    this.rule = rule;
  }

  public ClientMatchingPolicyDTO getOriginClient() {
    return originClient;
  }

  public void setOriginClient(ClientMatchingPolicyDTO originClient) {
    this.originClient = originClient;
  }

  public ClientMatchingPolicyDTO getDestinationClient() {
    return destinationClient;
  }

  public void setDestinationClient(ClientMatchingPolicyDTO destinationClient) {
    this.destinationClient = destinationClient;
  }

  public List<ExchangeScopePolicyDTO> getScopePolicies() {
    return scopePolicies;
  }

  public void setScopePolicies(List<ExchangeScopePolicyDTO> scopePolicies) {
    this.scopePolicies = scopePolicies;
  }

  public static ExchangePolicyDTO denyPolicy(String description) {
    ExchangePolicyDTO dto = new ExchangePolicyDTO();
    dto.setDescription(description);
    dto.setRule(PolicyRule.DENY);
    return dto;
  }

  public static ExchangePolicyDTO permitPolicy(String description) {
    ExchangePolicyDTO dto = new ExchangePolicyDTO();
    dto.setDescription(description);
    dto.setRule(PolicyRule.PERMIT);
    return dto;
  }


}
