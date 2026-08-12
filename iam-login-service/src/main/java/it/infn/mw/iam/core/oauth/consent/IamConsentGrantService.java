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

import java.time.Clock;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.springframework.stereotype.Service;

import it.infn.mw.iam.persistence.model.ConsentGrant;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.repository.IamConsentGrantRepository;

@Service
public class IamConsentGrantService implements ConsentGrantService {

  private final Clock clock;
  private final IamConsentGrantRepository repository;

  public IamConsentGrantService(Clock clock, IamConsentGrantRepository repository) {

    this.clock = clock;
    this.repository = repository;
  }

  @Override
  public ConsentGrant createConsentGrant(ClientDetailsEntity client, String userId, Date timeoutDate,
      Set<String> allowedScopes) {

    ConsentGrant cg = new ConsentGrant();
    Date now = Date.from(clock.instant());
    cg.setCreationDate(now);
    cg.setAccessDate(now);
    cg.setClient(client);
    cg.setUserId(userId);
    cg.setTimeoutDate(timeoutDate);
    cg.setAllowedScopes(allowedScopes);
    return save(cg);
  }

  @Override
  public List<ConsentGrant> getAll() {

    return repository.findAll();
  }

  @Override
  public List<ConsentGrant> getByClientIdAndUserId(String clientId, String userId) {

    return repository.findByClient_ClientIdAndUserId(clientId, userId);
  }

  @Override
  public ConsentGrant save(ConsentGrant consentGrant) {

    return repository.saveAndFlush(consentGrant);
  }

  @Override
  public Optional<ConsentGrant> getById(Long id) {

    return repository.findById(id);
  }

  @Override
  public void remove(ConsentGrant consentGrant) {

    repository.delete(consentGrant);
  }

  @Override
  public List<ConsentGrant> getByUserId(String userId) {

    return repository.findByUserId(userId);
  }

  @Override
  public List<ConsentGrant> getByClientId(String clientId) {

    return repository.findByUserId(clientId);
  }

  @Override
  public boolean isExpired(ConsentGrant consentGrant) {
    if (consentGrant.getTimeoutDate() == null) {
      return false;
    }
    return clock.instant().isAfter(consentGrant.getTimeoutDate().toInstant());
  }

}
