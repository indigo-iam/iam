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

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.openid.connect.model.ApprovedSite;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.persistence.repository.IamApprovedSiteRepository;

@Service
public class IamApprovedSiteService implements ApprovedSiteService {

  private final Clock clock;
  private final IamApprovedSiteRepository siteRepository;

  public IamApprovedSiteService(Clock clock, IamApprovedSiteRepository siteRepository) {

    this.clock = clock;
    this.siteRepository = siteRepository;
  }

  @Override
  public ApprovedSite createApprovedSite(ClientDetailsEntity client, String userId, Date timeoutDate,
      Set<String> allowedScopes) {

    ApprovedSite as = new ApprovedSite();
    Date now = Date.from(clock.instant());
    as.setCreationDate(now);
    as.setAccessDate(now);
    as.setClient(client);
    as.setUserId(userId);
    as.setTimeoutDate(timeoutDate);
    as.setAllowedScopes(allowedScopes);
    return save(as);
  }

  @Override
  public List<ApprovedSite> getAll() {

    return siteRepository.findAll();
  }

  @Override
  public List<ApprovedSite> getByClientIdAndUserId(String clientId, String userId) {

    return siteRepository.findByClient_ClientIdAndUserId(clientId, userId);
  }

  @Override
  public ApprovedSite save(ApprovedSite approvedSite) {

    return siteRepository.saveAndFlush(approvedSite);
  }

  @Override
  public Optional<ApprovedSite> getById(Long id) {

    return siteRepository.findById(id);
  }

  @Override
  public void remove(ApprovedSite approvedSite) {

    siteRepository.delete(approvedSite);
  }

  @Override
  public List<ApprovedSite> getByUserId(String userId) {

    return siteRepository.findByUserId(userId);
  }

  @Override
  public List<ApprovedSite> getByClientId(String clientId) {

    return siteRepository.findByUserId(clientId);
  }

  @Override
  public void clearApprovedSitesForClient(String clientId) {

    siteRepository.findByClient_ClientId(clientId).forEach(this::remove);
  }

  @Override
  public boolean isExpired(ApprovedSite approvedSite) {
    if (approvedSite.getTimeoutDate() == null) {
      return false;
    }
    return clock.instant().isAfter(approvedSite.getTimeoutDate().toInstant());
  }

}
