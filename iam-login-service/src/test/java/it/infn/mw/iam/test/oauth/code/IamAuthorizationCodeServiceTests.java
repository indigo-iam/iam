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
package it.infn.mw.iam.test.oauth.code;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

import it.infn.mw.iam.core.IamAuthenticationHolderService;
import it.infn.mw.iam.core.oauth.code.IamAuthorizationCodeService;
import it.infn.mw.iam.persistence.model.AuthenticationHolderEntity;
import it.infn.mw.iam.persistence.model.AuthorizationCodeEntity;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.repository.IamAuthorizationCodeRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;

@SuppressWarnings("deprecation")
@ExtendWith(MockitoExtension.class)
class IamAuthorizationCodeServiceTests {

  @Mock
  private IamAuthorizationCodeRepository codeRepository;

  @Mock
  private IamClientRepository clientRepository;

  @Mock
  private IamAuthenticationHolderService authenticationHolderService;

  @Mock
  private OAuth2Authentication authentication;

  @Mock
  private OAuth2Request request;

  @Test
  void authorizationCodeUses32RandomBytesEncodedAsBase64UrlWithoutPadding() {

    Instant now = Instant.parse("2026-01-01T00:00:00Z");
    Clock clock = Clock.fixed(now, ZoneOffset.UTC);

    byte[] expectedBytes = new byte[32];
    for (int i = 0; i < expectedBytes.length; i++) {
      expectedBytes[i] = (byte) (0xf0 + i);
    }

    SecureRandom random = new SecureRandom() {

      private static final long serialVersionUID = 1L;

      @Override
      public void nextBytes(byte[] bytes) {
        assertEquals(32, bytes.length);
        System.arraycopy(expectedBytes, 0, bytes, 0, bytes.length);
      }
    };

    IamAuthorizationCodeService service = new IamAuthorizationCodeService(clock, codeRepository,
        clientRepository, authenticationHolderService, random);

    ClientDetailsEntity client = new ClientDetailsEntity();
    AuthenticationHolderEntity holder = new AuthenticationHolderEntity();

    when(authentication.getOAuth2Request()).thenReturn(request);
    when(request.getClientId()).thenReturn("test-client");
    when(clientRepository.findByClientId("test-client")).thenReturn(Optional.of(client));
    when(authenticationHolderService.createAndSave(authentication, client)).thenReturn(holder);

    String code = service.createAuthorizationCode(authentication);

    assertTrue(code.matches("[A-Za-z0-9_-]{43}"));
    assertArrayEquals(expectedBytes, Base64.getUrlDecoder().decode(code));

    ArgumentCaptor<AuthorizationCodeEntity> captor =
        ArgumentCaptor.forClass(AuthorizationCodeEntity.class);
    verify(codeRepository).save(captor.capture());

    AuthorizationCodeEntity saved = captor.getValue();
    assertEquals(code, saved.getCode());
    assertSame(holder, saved.getAuthenticationHolder());
    assertEquals(Date.from(now.plusSeconds(300)), saved.getExpiration());
  }
}
