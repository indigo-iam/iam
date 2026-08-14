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
package it.infn.mw.iam.core.oauth.consent;

import java.util.List;
import java.util.Optional;

import org.springframework.stereotype.Service;

import it.infn.mw.iam.persistence.model.ConsentExemption;
import it.infn.mw.iam.persistence.repository.IamConsentExemptionRepository;

@Service
public class DefaultConsentExemptionService implements ConsentExemptionService {

  private final IamConsentExemptionRepository repository;

  public DefaultConsentExemptionService(IamConsentExemptionRepository repository) {
    this.repository = repository;
  }

  @Override
  public Optional<ConsentExemption> findById(Long id) {
    return repository.findById(id);
  }

  @Override
  public void remove(ConsentExemption consentExemption) {
    repository.delete(consentExemption);
  }

  @Override
  public ConsentExemption save(ConsentExemption consentExemption) {
    return repository.save(consentExemption);
  }

  @Override
  public List<ConsentExemption> findAll() {
    return repository.findAll();
  }

  @Override
  public Optional<ConsentExemption> findByClientId(String clientId) {
    return repository.findByClientId(clientId);
  }

}
