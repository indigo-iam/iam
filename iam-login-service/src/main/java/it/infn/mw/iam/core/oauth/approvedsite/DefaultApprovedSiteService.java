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
package it.infn.mw.iam.core.oauth.approvedsite;

import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.core.oauth.revocation.TokenRevocationService;
import it.infn.mw.iam.core.stats.StatsService;
import it.infn.mw.iam.persistence.model.ApprovedSite;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.OAuth2AccessTokenEntity;
import it.infn.mw.iam.persistence.repository.IamApprovedSiteRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;

@Service
public class DefaultApprovedSiteService implements ApprovedSiteService {

  private static final Logger logger = LoggerFactory.getLogger(DefaultApprovedSiteService.class);

  @Autowired
  private IamApprovedSiteRepository approvedSiteRepository;

  @Autowired
  private TokenRevocationService revocationService;

  @Autowired
  private IamOAuthAccessTokenRepository accessTokenRepository;

  @Autowired
  private StatsService statsService;

  @Override
  public Collection<ApprovedSite> getAll() {
    return approvedSiteRepository.findAll();
  }

  @Override
  @Transactional(value = "defaultTransactionManager")
  public ApprovedSite save(ApprovedSite approvedSite) {

    ApprovedSite a = approvedSiteRepository.saveAndFlush(approvedSite);
    statsService.resetCache();
    return a;
  }

  @Override
  public ApprovedSite getById(Long id) {
    return approvedSiteRepository.getById(id);
  }

  @Override
  @Transactional(value = "defaultTransactionManager")
  public void remove(ApprovedSite approvedSite) {

    // Remove any associated access and refresh tokens
    List<OAuth2AccessTokenEntity> accessTokens = getApprovedAccessTokens(approvedSite);

    for (OAuth2AccessTokenEntity token : accessTokens) {
      if (token.getRefreshToken() != null) {
        revocationService.revokeRefreshToken(token.getRefreshToken());
      }
      revocationService.revokeAccessToken(token);
    }
    approvedSiteRepository.delete(approvedSite);
    statsService.resetCache();
  }

  @Override
  @Transactional(value = "defaultTransactionManager")
  public ApprovedSite createApprovedSite(ClientDetailsEntity client, IamAccount account, Date timeoutDate,
      Set<String> allowedScopes) {

    ApprovedSite as = new ApprovedSite();

    Date now = new Date();
    as.setCreationDate(now);
    as.setAccessDate(now);
    as.setClient(client);
    as.setAccount(account);
    as.setTimeoutDate(timeoutDate);
    as.setAllowedScopes(allowedScopes);

    return save(as);
  }

  @Override
  public Collection<ApprovedSite> getByClientAndUser(ClientDetailsEntity client, IamAccount account) {

    return approvedSiteRepository.findByClientIdAndUserId(client.getClientId(), account.getUsername());
  }

  @Override
  public Collection<ApprovedSite> getByUser(IamAccount account) {

    return approvedSiteRepository.findByUserId(account.getUsername());
  }

  @Override
  public Collection<ApprovedSite> getByClient(ClientDetailsEntity client) {

    return approvedSiteRepository.findByClientId(client.getClientId());
  }


  @Override
  public void clearApprovedSitesForClient(ClientDetailsEntity client) {

    Collection<ApprovedSite> approvedSites =
        approvedSiteRepository.findByClientId(client.getClientId());
    approvedSites.forEach(this::remove);
  }

  @Override
  public void clearExpiredSites() {

    logger.debug("Clearing expired approved sites");

    Collection<ApprovedSite> expiredSites = getExpired();
    if (expiredSites.size() > 0) {
      logger.info("Found " + expiredSites.size() + " expired approved sites.");
    }
    if (expiredSites != null) {
      for (ApprovedSite expired : expiredSites) {
        remove(expired);
      }
    }
  }

  private Collection<ApprovedSite> getExpired() {

    return approvedSiteRepository.findExpired();
  }

  @Override
  public List<OAuth2AccessTokenEntity> getApprovedAccessTokens(ApprovedSite approvedSite) {

    return accessTokenRepository.findByApprovedSiteId(approvedSite.getId());
  }

}
