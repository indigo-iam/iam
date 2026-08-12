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
package it.infn.mw.iam.core.gc;

import java.time.Clock;
import java.util.Date;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.api.common.OffsetPageable;
import it.infn.mw.iam.persistence.model.ConsentGrant;
import it.infn.mw.iam.persistence.model.AuthenticationHolderEntity;
import it.infn.mw.iam.persistence.model.AuthorizationCodeEntity;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.model.DeviceCode;
import it.infn.mw.iam.persistence.model.IamRevokedAccessToken;
import it.infn.mw.iam.persistence.model.OAuth2AccessTokenEntity;
import it.infn.mw.iam.persistence.model.OAuth2RefreshTokenEntity;
import it.infn.mw.iam.persistence.repository.IamConsentGrantRepository;
import it.infn.mw.iam.persistence.repository.IamAuthenticationHolderRepository;
import it.infn.mw.iam.persistence.repository.IamAuthorizationCodeRepository;
import it.infn.mw.iam.persistence.repository.IamDeviceCodeRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;
import it.infn.mw.iam.persistence.repository.IamRevokedAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;

@Service
public class DefaultGarbageCollector implements GarbageCollector {

  public static final Logger LOG = LoggerFactory.getLogger(DefaultGarbageCollector.class);

  private final Clock clock;
  private final IamConsentGrantRepository approvedSiteRepository;
  private final IamOAuthAccessTokenRepository accessTokenRepo;
  private final IamOAuthRefreshTokenRepository refreshTokenRepo;
  private final IamDeviceCodeRepository deviceCodeRepo;
  private final IamAuthenticationHolderRepository authenticationHolderRepository;
  private final IamRevokedAccessTokenRepository revokedAccessTokenRepo;
  private final IamAuthorizationCodeRepository authzCodeRepo;
  private final IamClientRepository clientRepository;
  private final ClientService clientService;

  public DefaultGarbageCollector(Clock clock, IamConsentGrantRepository approvedSiteRepository,
      IamOAuthAccessTokenRepository accessTokenRepo,
      IamOAuthRefreshTokenRepository refreshTokenRepo, IamDeviceCodeRepository deviceCodeRepo,
      IamAuthenticationHolderRepository authenticationHolderRepository,
      IamRevokedAccessTokenRepository revokedAccessTokenRepo,
      IamAuthorizationCodeRepository authzCodeRepo, IamClientRepository clientRepository,
      ClientService clientService) {

    this.clock = clock;
    this.approvedSiteRepository = approvedSiteRepository;
    this.accessTokenRepo = accessTokenRepo;
    this.refreshTokenRepo = refreshTokenRepo;
    this.deviceCodeRepo = deviceCodeRepo;
    this.authenticationHolderRepository = authenticationHolderRepository;
    this.revokedAccessTokenRepo = revokedAccessTokenRepo;
    this.authzCodeRepo = authzCodeRepo;
    this.clientRepository = clientRepository;
    this.clientService = clientService;
  }

  @Override
  @SchedulerLock(name = "deleteExpiredApprovedSites", lockAtLeastFor = "1m", lockAtMostFor = "15m")
  @Transactional(value = "defaultTransactionManager")
  public void clearExpiredConsentGrants(int count) {

    Page<ConsentGrant> expiredSites = approvedSiteRepository
      .getExpiredCodes(Date.from(clock.instant()), new OffsetPageable(0, count));
    LOG.debug("Found {} expired approved sites", expiredSites.getTotalElements());
    approvedSiteRepository.deleteAll(expiredSites);
    if (expiredSites.getTotalElements() > 0) {
      LOG.info("Removed {} expired approved sites", expiredSites.getTotalElements());
    }
  }

  @Override
  @SchedulerLock(name = "deleteExpiredAuthzCodes", lockAtLeastFor = "1m", lockAtMostFor = "15m")
  @Transactional(value = "defaultTransactionManager")
  public void clearExpiredAuthorizationCodes(int count) {

    Page<AuthorizationCodeEntity> expiredAuthzCodes = authzCodeRepo
      .getExpiredAuthorizationCodes(Date.from(clock.instant()), new OffsetPageable(0, count));
    authzCodeRepo.deleteAll(expiredAuthzCodes);
    if (expiredAuthzCodes.getTotalElements() > 0) {
      LOG.info("Removed {} of {} expired authorization codes",
          expiredAuthzCodes.getNumberOfElements(), expiredAuthzCodes.getTotalElements());
    }
  }

  @Override
  @SchedulerLock(name = "deleteExpiredDeviceCodes", lockAtLeastFor = "1m", lockAtMostFor = "15m")
  @Transactional(value = "defaultTransactionManager")
  public void clearExpiredDeviceCodes(int count) {

    List<DeviceCode> expiredDeviceCodes = deviceCodeRepo.findExpired(Date.from(clock.instant()));
    deviceCodeRepo.deleteAll(expiredDeviceCodes);
    if (!expiredDeviceCodes.isEmpty()) {
      LOG.info("Removed {} expired device codes", expiredDeviceCodes.size());
    }
  }

  @Override
  @SchedulerLock(name = "deleteExpiredRevokedTokens", lockAtLeastFor = "1m", lockAtMostFor = "15m")
  @Transactional(value = "defaultTransactionManager")
  public void clearExpiredRevokedTokens(int count) {

    Page<IamRevokedAccessToken> revokedTokens = revokedAccessTokenRepo
      .findExpired(Date.from(clock.instant()), new OffsetPageable(0, count));
    revokedAccessTokenRepo.deleteAll(revokedTokens);
    if (revokedTokens.getTotalElements() > 0) {
      LOG.info("Removed {} of {} revoked access tokens", revokedTokens.getNumberOfElements(),
          revokedTokens.getTotalElements());
    }
  }

  @Override
  @SchedulerLock(name = "deleteExpiredAccessTokens", lockAtLeastFor = "1m", lockAtMostFor = "15m")
  @Transactional(value = "defaultTransactionManager")
  public void clearExpiredAccessTokens(int count) {

    Page<OAuth2AccessTokenEntity> expiredAccessTokens =
        accessTokenRepo.findExpiredTokens(new OffsetPageable(0, count), Date.from(clock.instant()));
    accessTokenRepo.deleteAll(expiredAccessTokens);
    if (expiredAccessTokens.getTotalElements() > 0) {
      LOG.info("Removed {} of {} expired access tokens", expiredAccessTokens.getNumberOfElements(),
          expiredAccessTokens.getTotalElements());
    }
  }

  @Override
  @SchedulerLock(name = "deleteExpiredRefreshTokens", lockAtLeastFor = "1m", lockAtMostFor = "15m")
  @Transactional(value = "defaultTransactionManager")
  public void clearExpiredRefreshTokens(int count) {

    Page<OAuth2RefreshTokenEntity> expiredRefreshTokens = refreshTokenRepo
      .findExpiredTokens(new OffsetPageable(0, count), Date.from(clock.instant()));
    refreshTokenRepo.deleteAll(expiredRefreshTokens);
    if (expiredRefreshTokens.getTotalElements() > 0) {
      LOG.info("Removed {} of {} expired refresh tokens",
          expiredRefreshTokens.getNumberOfElements(), expiredRefreshTokens.getTotalElements());
    }
  }

  @Override
  @SchedulerLock(name = "deleteAuthenticationHolder", lockAtLeastFor = "1m", lockAtMostFor = "15m")
  @Transactional(value = "defaultTransactionManager")
  public void clearOrphanedAuthenticationHolder(int count) {

    Page<AuthenticationHolderEntity> orphanedHolders = authenticationHolderRepository
      .getOrphans(new OffsetPageable(0, count), Date.from(clock.instant()));
    authenticationHolderRepository.deleteAll(orphanedHolders);
    if (orphanedHolders.getTotalElements() > 0) {
      LOG.info("Removed {} of {} orphaned authentication holders",
          orphanedHolders.getNumberOfElements(), orphanedHolders.getTotalElements());
    }
  }

  @Override
  @SchedulerLock(name = "suspendExpiredClients", lockAtLeastFor = "1m", lockAtMostFor = "15m")
  @Transactional(value = "defaultTransactionManager")
  public void clearExpiredClients(int count) {

    Page<ClientDetailsEntity> expiredClients = clientRepository
      .findActiveClientsExpiredBefore(new OffsetPageable(0, count), Date.from(clock.instant()));
    expiredClients.getContent()
      .forEach(client -> clientService.updateClientStatus(client, false, "expired_client_task"));
    if (expiredClients.getTotalElements() > 0) {
      LOG.info("Suspended {} of {} expired clients", expiredClients.getNumberOfElements(),
          expiredClients.getTotalElements());
    }
  }

}
