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
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.audit.events.scope_policy.ScopePolicyCreatedEvent;
import it.infn.mw.iam.audit.events.scope_policy.ScopePolicyDeletedEvent;
import it.infn.mw.iam.audit.events.scope_policy.ScopePolicyUpdatedEvent;
import it.infn.mw.iam.persistence.model.IamScopePolicy;
import it.infn.mw.iam.persistence.repository.IamScopePolicyRepository;

@Service
public class DefaultScopePolicyService implements ScopePolicyService {

  private final IamScopePolicyRepository scopePolicyRepo;
  private final IamScopePolicyConverter converter;
  private final ApplicationEventPublisher publisher;
  
  @Autowired
  public DefaultScopePolicyService(IamScopePolicyRepository scopePolicyRepo,
      IamScopePolicyConverter converter,
      ApplicationEventPublisher publisher) {
    this.scopePolicyRepo = scopePolicyRepo;
    this.converter = converter;
    this.publisher = publisher;
  }
  
  private ScopePolicyNotFoundError notFoundError(Long id) {
    return new ScopePolicyNotFoundError(String.format("No scope policy found for id: %d", id));
  }

  @Override
  public Iterable<IamScopePolicy> findAllScopePolicies() {
    return scopePolicyRepo.findAll();
  }


  @Override
  public Optional<IamScopePolicy> findScopePolicyById(Long policyId) {
    return scopePolicyRepo.findById(policyId);
  }

  @Override
  public void deleteScopePolicyById(Long policyId) {
    IamScopePolicy sp =
        scopePolicyRepo.findById(policyId).orElseThrow(() -> notFoundError(policyId));

    scopePolicyRepo.delete(sp);
    publisher.publishEvent(new ScopePolicyDeletedEvent(this, sp));
  }

  @Override
  public IamScopePolicy createScopePolicy(ScopePolicyDTO scopePolicy) {
    IamScopePolicy sp = converter.toModel(scopePolicy);
    Date now = new Date();
    sp.setCreationTime(now);
    sp.setLastUpdateTime(now);

    List<IamScopePolicy> equivalentPolicies = scopePolicyRepo.findEquivalentPolicies(sp);

    if (!equivalentPolicies.isEmpty()) {
      throw new DuplicateScopePolicyError(equivalentPolicies);
    }

    sp.linkAccount();
    sp.linkGroup();

    sp = scopePolicyRepo.save(sp);
    publisher.publishEvent(new ScopePolicyCreatedEvent(this, sp));
    return sp;

  }

  @Override
  public IamScopePolicy updateScopePolicy(ScopePolicyDTO scopePolicy) {
    IamScopePolicy updatedPolicy = converter.toModel(scopePolicy);
    
    IamScopePolicy existingPolicy =
        scopePolicyRepo.findById(scopePolicy.getId()).orElseThrow(() -> notFoundError(scopePolicy.getId()));
    
    List<IamScopePolicy> equivalentPolicies = scopePolicyRepo.findEquivalentPolicies(updatedPolicy);
    
    // The new policy can be equivalent to the existing policy it will replace 
    equivalentPolicies.remove(existingPolicy);
    
    if (!equivalentPolicies.isEmpty()){
      throw new DuplicateScopePolicyError(equivalentPolicies);
    }
    
    existingPolicy.from(updatedPolicy);
    existingPolicy.setLastUpdateTime(new Date());
    
    existingPolicy = scopePolicyRepo.save(existingPolicy);
    publisher.publishEvent(new ScopePolicyUpdatedEvent(this, existingPolicy));
    return existingPolicy;
  }

}
