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
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;

import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.core.gc.DefaultGarbageCollector;
import it.infn.mw.iam.persistence.model.ConsentGrant;
import it.infn.mw.iam.persistence.model.AuthenticationHolderEntity;
import it.infn.mw.iam.persistence.model.AuthorizationCodeEntity;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.model.ClientRelyingPartyEntity;
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

class GarbageCollectorTests {

  @Mock
  private IamConsentGrantRepository consentGrantRepository;
  @Mock
  private IamOAuthAccessTokenRepository accessTokenRepo;
  @Mock
  private IamOAuthRefreshTokenRepository refreshTokenRepo;
  @Mock
  private IamDeviceCodeRepository deviceCodeRepo;
  @Mock
  private IamAuthenticationHolderRepository authenticationHolderRepository;
  @Mock
  private IamRevokedAccessTokenRepository revokedAccessTokenRepo;
  @Mock
  private IamAuthorizationCodeRepository authzCodeRepo;
  @Mock
  private IamClientRepository clientRepository;
  @Mock
  private ClientService clientService;
  @Mock
  private Clock clock;

  private DefaultGarbageCollector gc;

  @BeforeEach
  void setup() {
    MockitoAnnotations.openMocks(this);

    gc = new DefaultGarbageCollector(clock, consentGrantRepository, accessTokenRepo,
        refreshTokenRepo, deviceCodeRepo, authenticationHolderRepository, revokedAccessTokenRepo,
        authzCodeRepo, clientRepository, clientService);
  }

  @Test
  void testClearExpiredConsentGrants() {

    ConsentGrant code = mock(ConsentGrant.class);
    Page<ConsentGrant> response = new PageImpl<>(List.of(code), PageRequest.of(0, 1), 1);
    when(clock.instant()).thenReturn(Instant.now());
    when(consentGrantRepository.getExpiredCodes(any(), any())).thenReturn(response);
    gc.clearExpiredConsentGrants(10);
    verify(consentGrantRepository).deleteAll(response);
  }

  @Test
  void testClearExpiredAuthorizationCodes() {

    AuthorizationCodeEntity code = mock(AuthorizationCodeEntity.class);
    Page<AuthorizationCodeEntity> response = new PageImpl<>(List.of(code), PageRequest.of(0, 1), 1);
    when(clock.instant()).thenReturn(Instant.now());
    when(authzCodeRepo.getExpiredAuthorizationCodes(any(), any())).thenReturn(response);
    gc.clearExpiredAuthorizationCodes(10);
    verify(authzCodeRepo).deleteAll(response);
  }

  @Test
  void testClearExpiredDeviceCodes() {

    DeviceCode dc = mock(DeviceCode.class);
    when(clock.instant()).thenReturn(Instant.now());
    when(deviceCodeRepo.findExpired(any())).thenReturn(List.of(dc));
    gc.clearExpiredDeviceCodes(10);
    verify(deviceCodeRepo).deleteAll(List.of(dc));
  }

  @Test
  void testClearExpiredRevokedTokens() {

    IamRevokedAccessToken tok = mock(IamRevokedAccessToken.class);
    Page<IamRevokedAccessToken> response = new PageImpl<>(List.of(tok), PageRequest.of(0, 1), 1);
    when(clock.instant()).thenReturn(Instant.now());
    when(revokedAccessTokenRepo.findExpired(any(), any())).thenReturn(response);
    gc.clearExpiredRevokedTokens(10);
    verify(revokedAccessTokenRepo).deleteAll(response);
  }

  @Test
  void testClearExpiredAccessTokens() {

    OAuth2AccessTokenEntity tok = mock(OAuth2AccessTokenEntity.class);
    Page<OAuth2AccessTokenEntity> response = new PageImpl<>(List.of(tok), PageRequest.of(0, 1), 1);
    when(clock.instant()).thenReturn(Instant.now());
    when(accessTokenRepo.findExpiredTokens(any(), any())).thenReturn(response);
    gc.clearExpiredAccessTokens(10);
    verify(accessTokenRepo).deleteAll(response);
  }

  @Test
  void testClearExpiredRefreshTokens() {

    OAuth2RefreshTokenEntity tok = mock(OAuth2RefreshTokenEntity.class);
    Page<OAuth2RefreshTokenEntity> response = new PageImpl<>(List.of(tok), PageRequest.of(0, 1), 1);
    when(clock.instant()).thenReturn(Instant.now());
    when(refreshTokenRepo.findExpiredTokens(any(), any())).thenReturn(response);
    gc.clearExpiredRefreshTokens(10);
    verify(refreshTokenRepo).deleteAll(response);
  }

  @Test
  void testClearOrphanedAuthenticationHolder() {

    AuthenticationHolderEntity holder = mock(AuthenticationHolderEntity.class);
    Page<AuthenticationHolderEntity> response =
        new PageImpl<>(List.of(holder), PageRequest.of(0, 1), 1);
    when(clock.instant()).thenReturn(Instant.now());
    when(authenticationHolderRepository.getOrphans(any(), any())).thenReturn(response);
    gc.clearOrphanedAuthenticationHolder(10);
    verify(authenticationHolderRepository).deleteAll(response);
  }

  @Test
  void testSuspendExpiredClients() {

    Date aMinuteBefore = Date.from(Instant.now().minusSeconds(60));
    ClientDetailsEntity client = mock(ClientDetailsEntity.class);
    when(client.isActive()).thenReturn(true);
    ClientRelyingPartyEntity rp = mock(ClientRelyingPartyEntity.class);
    when(rp.getExpiration()).thenReturn(aMinuteBefore);
    when(client.getClientRelyingParty()).thenReturn(rp);

    Page<ClientDetailsEntity> response =
        new PageImpl<>(List.of(client), PageRequest.of(0, 1), 1);
    when(clock.instant()).thenReturn(Instant.now());
    when(clientRepository.findActiveClientsExpiredBefore(any(), any())).thenReturn(response);
    gc.clearExpiredClients(10);
    verify(clientService).updateClientStatus(eq(client), eq(false), any());
  }
}
