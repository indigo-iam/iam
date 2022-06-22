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
package it.infn.mw.iam.persistence.repository;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.persistence.model.IamScopePolicy;

@Component
public class IamScopePolicyRepositoryImpl implements IamScopePolicyRepositoryCustom {

  @Autowired
  IamScopePolicyRepository repo;

  @Override
  public List<IamScopePolicy> findEquivalentPolicies(IamScopePolicy p) {

    List<IamScopePolicy> equivalentPolicies;

    if (p.getGroup() != null) {
      equivalentPolicies = repo.findByGroupAndRule(p.getGroup(), p.getRule());
    } else if (p.getAccount() != null) {
      equivalentPolicies = repo.findByAccountAndRule(p.getAccount(), p.getRule());
    } else {
      equivalentPolicies = repo.findDefaultPoliciesByRule(p.getRule());
    }

    if (p.getScopes().isEmpty()) {
      return equivalentPolicies.stream()
        .filter(ep -> ep.getScopes().isEmpty())
        .collect(Collectors.toList());
    }

    equivalentPolicies = equivalentPolicies.stream()
      .filter(ep -> ep.getScopes().containsAll(p.getScopes()))
      .collect(Collectors.toList());

    return equivalentPolicies;
  }

}
