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

import java.util.ArrayList;
import java.util.List;

import org.springframework.stereotype.Service;

import it.infn.mw.iam.api.scope_policy.ScopePolicyController.OpaPolicies;
import it.infn.mw.iam.persistence.model.IamScopePolicy;
import it.infn.mw.iam.persistence.model.IamScopePolicy.MatchingPolicy;

@Service 
public class OpaBundleService {

  private final ScopePolicyService policyService;
  private final IamScopePolicyConverter converter;

  public OpaBundleService(ScopePolicyService policyService, IamScopePolicyConverter converter) {
    this.policyService = policyService;
    this.converter = converter;
  }

  public OpaPolicies getPolicies() {
    Iterable<IamScopePolicy> policies = policyService.findAllScopePolicies();
    List<OpaPolicies.OpaPolicy> dtos = new ArrayList<>();

    policies.forEach(p -> {
      if (!p.getMatchingPolicy().equals(MatchingPolicy.REGEXP)) {
        dtos.add(converter.toOpaPolicyDTO(p));
      }
    });

    return new OpaPolicies(dtos);
  }
}
