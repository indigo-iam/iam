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

import java.util.Collection;

import org.mitre.data.DefaultPageCriteria;
import org.mitre.oauth2.model.AuthenticationHolderEntity;
import org.mitre.oauth2.model.AuthorizationCodeEntity;
import org.mitre.oauth2.model.DeviceCode;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.mitre.oauth2.repository.AuthenticationHolderRepository;
import org.mitre.oauth2.repository.AuthorizationCodeRepository;
import org.mitre.oauth2.repository.impl.DeviceCodeRepository;
import org.mitre.openid.connect.service.ApprovedSiteService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.api.common.OffsetPageable;
import it.infn.mw.iam.persistence.model.IamRevokedAccessToken;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;
import it.infn.mw.iam.persistence.repository.IamRevokedAccessTokenRepository;

@Service
public class DefaultGarbageCollector implements GarbageCollector {

  public static final Logger LOG = LoggerFactory.getLogger(DefaultGarbageCollector.class);

  private final ApprovedSiteService approvedSiteService;
  private final IamOAuthAccessTokenRepository accessTokenRepo;
  private final IamOAuthRefreshTokenRepository refreshTokenRepo;
  private final DeviceCodeRepository deviceCodeRepo;
  private final AuthenticationHolderRepository authenticationHolderRepository;
  private final IamRevokedAccessTokenRepository revokedAccessTokenRepo;
  private final AuthorizationCodeRepository authzCodeRepo;

  public DefaultGarbageCollector(ApprovedSiteService approvedSiteService,
      IamOAuthAccessTokenRepository accessTokenRepo,
      IamOAuthRefreshTokenRepository refreshTokenRepo, DeviceCodeRepository deviceCodeRepo,
      AuthenticationHolderRepository authenticationHolderRepository,
      IamRevokedAccessTokenRepository revokedAccessTokenRepo,
      AuthorizationCodeRepository authzCodeRepo) {

    this.approvedSiteService = approvedSiteService;
    this.accessTokenRepo = accessTokenRepo;
    this.refreshTokenRepo = refreshTokenRepo;
    this.deviceCodeRepo = deviceCodeRepo;
    this.authenticationHolderRepository = authenticationHolderRepository;
    this.revokedAccessTokenRepo = revokedAccessTokenRepo;
    this.authzCodeRepo = authzCodeRepo;
  }

  @Override
  @Transactional(value = "defaultTransactionManager")
  public void clearExpiredApprovedSites(int count) {
    approvedSiteService.clearExpiredSites();
  }

  @Override
  @Transactional(value = "defaultTransactionManager")
  public void clearExpiredAuthorizationCodes(int count) {

    Collection<AuthorizationCodeEntity> expiredAuthzCodes = authzCodeRepo.getExpiredCodes();
    LOG.debug("Found {} expired authorization codes", expiredAuthzCodes.size());
    expiredAuthzCodes.forEach(authzCodeRepo::remove);
  }

  @Override
  @Transactional(value = "defaultTransactionManager")
  public void clearExpiredDeviceCodes(int count) {

    Collection<DeviceCode> expiredDeviceCodes = deviceCodeRepo.getExpiredCodes();
    expiredDeviceCodes.forEach(deviceCodeRepo::remove);
    LOG.debug("Removed {} expired device codes", expiredDeviceCodes.size());
  }

  @Override
  @Transactional(value = "defaultTransactionManager")
  public void clearExpiredRevokedTokens(int count) {

    Page<IamRevokedAccessToken> revokedTokens =
        revokedAccessTokenRepo.findExpired(new OffsetPageable(0, 100));
    revokedTokens.forEach(revokedAccessTokenRepo::delete);
    LOG.debug("Removed {} revoked access tokens", revokedTokens.getTotalElements());
  }

  @Override
  @Transactional(value = "defaultTransactionManager")
  public void clearExpiredAccessTokens(int count) {

    Page<OAuth2AccessTokenEntity> expiredAccessTokens =
        accessTokenRepo.findExpiredTokens(new OffsetPageable(0, 100));
    expiredAccessTokens.forEach(accessTokenRepo::delete);
    LOG.debug("Removed {} expired access tokens", expiredAccessTokens.getNumberOfElements());
  }

  @Override
  public void clearExpiredRefreshTokens(int count) {

    Page<OAuth2RefreshTokenEntity> expiredRefreshTokens =
        refreshTokenRepo.findExpiredTokens(new OffsetPageable(0, 100));
    expiredRefreshTokens.forEach(refreshTokenRepo::delete);
    LOG.debug("Removed {} expired refresh tokens", expiredRefreshTokens.getNumberOfElements());
  }

  @Override
  public void clearOrphanedAuthenticationHolder(int count) {

    Collection<AuthenticationHolderEntity> orphanedHolders =
        authenticationHolderRepository.getOrphanedAuthenticationHolders(new DefaultPageCriteria());
    orphanedHolders.forEach(authenticationHolderRepository::remove);
    LOG.debug("Removed {} orphaned authentication holders", orphanedHolders.size());
  }

}