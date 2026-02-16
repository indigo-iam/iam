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

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.api.common.OffsetPageable;
import it.infn.mw.iam.core.AuthenticationHolderService;
import it.infn.mw.iam.core.oauth.approvedsite.ApprovedSiteService;
import it.infn.mw.iam.core.oauth.devicecode.DeviceCodeService;
import it.infn.mw.iam.persistence.model.AuthenticationHolderEntity;
import it.infn.mw.iam.persistence.model.AuthorizationCodeEntity;
import it.infn.mw.iam.persistence.model.IamRevokedAccessToken;
import it.infn.mw.iam.persistence.model.OAuth2AccessTokenEntity;
import it.infn.mw.iam.persistence.model.OAuth2RefreshTokenEntity;
import it.infn.mw.iam.persistence.repository.IamAuthorizationCodeRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;
import it.infn.mw.iam.persistence.repository.IamRevokedAccessTokenRepository;

@Service
public class DefaultGarbageCollector implements GarbageCollector {

  public static final Logger LOG = LoggerFactory.getLogger(DefaultGarbageCollector.class);

  private final ApprovedSiteService approvedSiteService;
  private final IamOAuthAccessTokenRepository accessTokenRepo;
  private final IamOAuthRefreshTokenRepository refreshTokenRepo;
  private final DeviceCodeService deviceCodeService;
  private final AuthenticationHolderService authHolderService;
  private final IamRevokedAccessTokenRepository revokedAccessTokenRepo;
  private final IamAuthorizationCodeRepository authzCodeRepo;

  public DefaultGarbageCollector(ApprovedSiteService approvedSiteService,
      IamOAuthAccessTokenRepository accessTokenRepo,
      IamOAuthRefreshTokenRepository refreshTokenRepo, DeviceCodeService deviceCodeService,
      AuthenticationHolderService authHolderService,
      IamRevokedAccessTokenRepository revokedAccessTokenRepo,
      IamAuthorizationCodeRepository authzCodeRepo) {

    this.approvedSiteService = approvedSiteService;
    this.accessTokenRepo = accessTokenRepo;
    this.refreshTokenRepo = refreshTokenRepo;
    this.deviceCodeService = deviceCodeService;
    this.authHolderService = authHolderService;
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

    List<AuthorizationCodeEntity> expiredAuthzCodes = authzCodeRepo.findExpired();
    LOG.debug("Found {} expired authorization codes", expiredAuthzCodes.size());
    expiredAuthzCodes.forEach(authzCodeRepo::delete);
  }

  @Override
  @Transactional(value = "defaultTransactionManager")
  public void clearExpiredDeviceCodes(int count) {

    int deleted = deviceCodeService.clearExpired();
    LOG.debug("Removed {} expired device codes", deleted);
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

    Page<AuthenticationHolderEntity> orphanedHolders =
        authHolderService.getOrphanedAuthenticationHolders(new OffsetPageable(0, 100));
    LOG.debug("Removing {} orphaned authentication holders ...",
        orphanedHolders.getContent().size());
    orphanedHolders.getContent().forEach(authHolderService::remove);
  }

}
