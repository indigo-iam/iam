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

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

import com.fasterxml.jackson.annotation.JsonInclude;

import it.infn.mw.iam.persistence.model.IamScopePolicy;
import it.infn.mw.iam.persistence.model.PolicyRule;

@JsonInclude(value = JsonInclude.Include.NON_EMPTY)
public class ExchangeScopePolicyDTO {

  @NotNull
  private PolicyRule rule;
  
  @NotNull
  private  IamScopePolicy.MatchingPolicy type;
  
  @Size(max = 256,
      message = "Invalid token exchange scope policy: the matchParam string must be at most 256 characters long")
  private String matchParam;
  
  public ExchangeScopePolicyDTO() {
    // empty on purpose
  }

  public PolicyRule getRule() {
    return rule;
  }

  public void setRule(PolicyRule rule) {
    this.rule = rule;
  }

  public IamScopePolicy.MatchingPolicy getType() {
    return type;
  }

  public void setType(IamScopePolicy.MatchingPolicy type) {
    this.type = type;
  }

  public String getMatchParam() {
    return matchParam;
  }

  public void setMatchParam(String matchParam) {
    this.matchParam = matchParam;
  }

}
