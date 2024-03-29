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
import java.util.stream.Collectors;

import it.infn.mw.iam.persistence.model.IamScopePolicy;

public class DuplicateScopePolicyError extends RuntimeException {

  /**
   * 
   */
  private static final long serialVersionUID = 1L;

  public static final String MSG_TEMPLATE =
      "Duplicate policy error: found equivalent policies in repository with ids: %s";


  public DuplicateScopePolicyError(List<IamScopePolicy> equivalentPolicies) {
    super(String.format(MSG_TEMPLATE, equivalentPolicies.stream()
      .map(IamScopePolicy::getId)
      .map(Object::toString)
      .collect(Collectors.joining(","))));
  }

}
