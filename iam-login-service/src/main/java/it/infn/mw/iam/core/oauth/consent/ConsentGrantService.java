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

import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import it.infn.mw.iam.persistence.model.ConsentGrant;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;

public interface ConsentGrantService {

  public ConsentGrant createConsentGrant(ClientDetailsEntity client, String userId, Date timeoutDate, Set<String> allowedScopes);

  public Optional<ConsentGrant> getById(Long id);

  public List<ConsentGrant> getAll();

  public List<ConsentGrant> getByUserId(String userId);

  public Collection<ConsentGrant> getByClientId(String clientId);

  public List<ConsentGrant> getByClientIdAndUserId(String clientId, String userId);

  public ConsentGrant save(ConsentGrant consentGrant);

  public void remove(ConsentGrant consentGrant);

  public boolean isExpired(ConsentGrant consentGrant);

}
