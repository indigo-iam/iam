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
package it.infn.mw.iam.test.core.gc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Collections;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mitre.oauth2.model.AuthenticationHolderEntity;
import org.mitre.oauth2.model.AuthorizationCodeEntity;
import org.mitre.oauth2.model.DeviceCode;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.mitre.oauth2.repository.AuthenticationHolderRepository;
import org.mitre.oauth2.repository.AuthorizationCodeRepository;
import org.mitre.oauth2.repository.impl.DeviceCodeRepository;
import org.mitre.openid.connect.service.ApprovedSiteService;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;

import it.infn.mw.iam.api.common.OffsetPageable;
import it.infn.mw.iam.core.gc.DefaultGarbageCollector;
import it.infn.mw.iam.persistence.model.IamRevokedAccessToken;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;
import it.infn.mw.iam.persistence.repository.IamRevokedAccessTokenRepository;

class GarbageCollectorTests {

  @Mock
  private ApprovedSiteService approvedSiteService;
  @Mock
  private IamOAuthAccessTokenRepository accessTokenRepo;
  @Mock
  private IamOAuthRefreshTokenRepository refreshTokenRepo;
  @Mock
  private DeviceCodeRepository deviceCodeRepo;
  @Mock
  private AuthenticationHolderRepository authenticationHolderRepository;
  @Mock
  private IamRevokedAccessTokenRepository revokedAccessTokenRepo;
  @Mock
  private AuthorizationCodeRepository authzCodeRepo;

  private DefaultGarbageCollector gc;

  @BeforeEach
  void setup() {
    MockitoAnnotations.openMocks(this);

    gc = new DefaultGarbageCollector(approvedSiteService, accessTokenRepo, refreshTokenRepo,
        deviceCodeRepo, authenticationHolderRepository, revokedAccessTokenRepo, authzCodeRepo);
  }

  @Test
  void testClearExpiredApprovedSites() {
    gc.clearExpiredApprovedSites(10);

    verify(approvedSiteService).clearExpiredSites();
  }

  @Test
  void testClearExpiredAuthorizationCodes() {
    AuthorizationCodeEntity code = mock(AuthorizationCodeEntity.class);
    when(authzCodeRepo.getExpiredCodes()).thenReturn(Collections.singletonList(code));

    gc.clearExpiredAuthorizationCodes(10);

    verify(authzCodeRepo).remove(code);
  }

  @Test
  void testClearExpiredDeviceCodes() {
    DeviceCode dc = mock(DeviceCode.class);
    when(deviceCodeRepo.getExpiredCodes()).thenReturn(Collections.singletonList(dc));

    gc.clearExpiredDeviceCodes(10);

    verify(deviceCodeRepo).remove(dc);
  }

  @Test
  void testClearExpiredRevokedTokens() {
    IamRevokedAccessToken tok = mock(IamRevokedAccessToken.class);
    Page<IamRevokedAccessToken> page = new PageImpl<>(Collections.singletonList(tok));

    when(revokedAccessTokenRepo.findExpired(any(OffsetPageable.class))).thenReturn(page);

    gc.clearExpiredRevokedTokens(10);

    verify(revokedAccessTokenRepo).delete(tok);
  }

  @Test
  void testClearExpiredAccessTokens() {
    OAuth2AccessTokenEntity tok = mock(OAuth2AccessTokenEntity.class);
    Page<OAuth2AccessTokenEntity> page = new PageImpl<>(Collections.singletonList(tok));

    when(accessTokenRepo.findExpiredTokens(any(OffsetPageable.class))).thenReturn(page);

    gc.clearExpiredAccessTokens(10);

    verify(accessTokenRepo).delete(tok);
  }

  @Test
  void testClearExpiredRefreshTokens() {
    OAuth2RefreshTokenEntity tok = mock(OAuth2RefreshTokenEntity.class);
    Page<OAuth2RefreshTokenEntity> page = new PageImpl<>(Collections.singletonList(tok));

    when(refreshTokenRepo.findExpiredTokens(any(OffsetPageable.class))).thenReturn(page);

    gc.clearExpiredRefreshTokens(10);

    verify(refreshTokenRepo).delete(tok);
  }

  @Test
  void testClearOrphanedAuthenticationHolder() {
    AuthenticationHolderEntity holder = mock(AuthenticationHolderEntity.class);
    when(authenticationHolderRepository.getOrphanedAuthenticationHolders(ArgumentMatchers.any()))
      .thenReturn(Collections.singletonList(holder));

    gc.clearOrphanedAuthenticationHolder(10);

    verify(authenticationHolderRepository).remove(holder);
  }
}
