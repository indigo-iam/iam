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
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.openid.connect.model.ApprovedSite;
import org.mitre.openid.connect.service.ApprovedSiteService;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.persistence.repository.IamApprovedSiteRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;

@SuppressWarnings("deprecation")
@Service
public class IamApprovedSiteService implements ApprovedSiteService {

  private final Clock clock;
  private final IamApprovedSiteRepository siteRepository;
  private final IamOAuthAccessTokenRepository accessTokenRepository;

  public IamApprovedSiteService(Clock clock, IamApprovedSiteRepository siteRepository,
      IamOAuthAccessTokenRepository accessTokenRepository) {

    this.clock = clock;
    this.siteRepository = siteRepository;
    this.accessTokenRepository = accessTokenRepository;
  }

  @Override
  public ApprovedSite createApprovedSite(String clientId, String userId, Date timeoutDate,
      Set<String> allowedScopes) {

    ApprovedSite as = new ApprovedSite();
    Date now = Date.from(clock.instant());
    as.setCreationDate(now);
    as.setAccessDate(now);
    as.setClientId(clientId);
    as.setUserId(userId);
    as.setTimeoutDate(timeoutDate);
    as.setAllowedScopes(allowedScopes);
    return save(as);
  }

  @Override
  public Collection<ApprovedSite> getAll() {

    return siteRepository.findAll();
  }

  @Override
  public Collection<ApprovedSite> getByClientIdAndUserId(String clientId, String userId) {

    return siteRepository.findByClientIdAndUserId(clientId, userId);
  }

  @Override
  public ApprovedSite save(ApprovedSite approvedSite) {

    return siteRepository.saveAndFlush(approvedSite);
  }

  @Override
  public ApprovedSite getById(Long id) {

    return siteRepository.findById(id).orElse(null);
  }

  @Override
  public void remove(ApprovedSite approvedSite) {

    siteRepository.delete(approvedSite);
  }

  @Override
  public Collection<ApprovedSite> getByUserId(String userId) {

    return siteRepository.findByUserId(userId);
  }

  @Override
  public Collection<ApprovedSite> getByClientId(String clientId) {

    return siteRepository.findByUserId(clientId);
  }

  @Override
  public void clearApprovedSitesForClient(ClientDetails client) {

    siteRepository.findByClientId(client.getClientId()).forEach(this::remove);
  }

  @Override
  public void clearExpiredSites() {

    // See @GarbageCollector
  }

  @Override
  public List<OAuth2AccessTokenEntity> getApprovedAccessTokens(ApprovedSite approvedSite) {

    return accessTokenRepository.findTokensForApprovedSite(approvedSite);
  }

}
