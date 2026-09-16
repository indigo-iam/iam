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

import java.util.List;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import it.infn.mw.iam.persistence.model.PolicyRule;
import it.infn.mw.iam.persistence.model.IamScopePolicy.MatchingPolicy;

public record OpaPolicies(List<OpaPolicy> policies) {

  public record OpaPolicy(@JsonInclude(JsonInclude.Include.NON_NULL) Actor actor,
      @JsonInclude(JsonInclude.Include.NON_EMPTY) String description,
      MatchingPolicy matchingPolicy, PolicyRule rule,
      @JsonInclude(JsonInclude.Include.NON_EMPTY) Set<String> scopes) {

    @JsonPropertyOrder({ "id", "name", "username", "type" })
    public record Actor(String id, @JsonIgnore String value, String type) {

      @JsonProperty("username")
      @JsonInclude(JsonInclude.Include.NON_NULL)
      public String username() {
        return "account".equals(type) ? value : null;
      }

      @JsonProperty("name")
      @JsonInclude(JsonInclude.Include.NON_NULL)
      public String name() {
        return "group".equals(type) ? value : null;
      }

    }
  }
}