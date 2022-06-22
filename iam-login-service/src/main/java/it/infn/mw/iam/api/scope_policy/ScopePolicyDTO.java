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

import java.util.Date;
import java.util.Set;

import javax.validation.Valid;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;

import javax.validation.constraints.NotBlank;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import it.infn.mw.iam.api.scim.controller.utils.JsonDateSerializer;
import it.infn.mw.iam.api.scope_policy.validation.ScopePolicy;

@ScopePolicy
public class ScopePolicyDTO {

  private Long id;

  @Size(max = 512,
      message = "Invalid scope policy: The description string must be at most 512 characters long")
  private String description;

  @JsonSerialize(using = JsonDateSerializer.class)
  private Date creationTime;

  @JsonSerialize(using = JsonDateSerializer.class)
  private Date lastUpdateTime;

  @Pattern(regexp = "PERMIT|DENY",
      message = "Invalid scope policy: allowed values for 'rule' are: 'PERMIT', 'DENY'")
  @NotBlank(message = "Invalid scope policy: rule cannot be empty")
  private String rule;

  @Pattern(regexp = "EQ|REGEXP|PATH",
      message = "Invalid scope policy: allowed values for 'matchingPolicy' are: 'EQ', 'REGEXP', 'PATH'")
  @NotBlank(message = "Invalid scope policy: matching policy cannot be empty or null")
  private String matchingPolicy = "EQ";

  @Valid
  private IamAccountRefDTO account;

  @Valid
  private GroupRefDTO group;

  private Set<String> scopes;

  public ScopePolicyDTO() {}

  @JsonCreator
  public ScopePolicyDTO(@JsonProperty("id") long id,
      @JsonProperty("description") String description,
      @JsonProperty("creationTime") Date creationTime,
      @JsonProperty("lastUpdateTime") Date lastUpdateTime, @JsonProperty("rule") String rule,
      @JsonProperty("matchingPolicy") String matchingPolicy,
      @JsonProperty("account") IamAccountRefDTO account, @JsonProperty("group") GroupRefDTO group,
      @JsonProperty("scopes") Set<String> scopes) {
    this.id = id;
    this.description = description;
    this.creationTime = creationTime;
    this.lastUpdateTime = lastUpdateTime;
    this.rule = rule;
    this.matchingPolicy = matchingPolicy;
    this.account = account;
    this.group = group;
    this.scopes = scopes;
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

  public String getRule() {
    return rule;
  }

  public void setRule(String rule) {
    this.rule = rule;
  }

  public IamAccountRefDTO getAccount() {
    return account;
  }

  public void setAccount(IamAccountRefDTO account) {
    this.account = account;
  }

  public GroupRefDTO getGroup() {
    return group;
  }

  public void setGroup(GroupRefDTO group) {
    this.group = group;
  }

  public Set<String> getScopes() {
    return scopes;
  }

  public void setScopes(Set<String> scopes) {
    this.scopes = scopes;
  }

  public String getMatchingPolicy() {
    return matchingPolicy;
  }

  public void setMatchingPolicy(String matchingPolicy) {
    this.matchingPolicy = matchingPolicy;
  }

}
