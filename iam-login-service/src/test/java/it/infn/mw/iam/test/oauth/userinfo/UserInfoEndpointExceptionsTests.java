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
package it.infn.mw.iam.test.oauth.userinfo;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import java.util.Optional;

import javax.security.auth.message.AuthException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.TokenUtils;
import it.infn.mw.iam.core.oauth.profile.JWTProfileResolver;
import it.infn.mw.iam.core.userinfo.IamUserInfoEndpoint;
import it.infn.mw.iam.core.userinfo.OAuth2AuthenticationScopeResolver;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;

@SuppressWarnings("deprecation")
@ExtendWith(MockitoExtension.class)
class UserInfoEndpointExceptionsTests {

  @Mock
  IamProperties iamProperties;
  @Mock
  JWTProfileResolver profileResolver;
  @Mock
  OAuth2AuthenticationScopeResolver scopeResolver;
  @Mock
  IamAccountRepository accountRepo;
  @Mock
  IamClientRepository clientRepo;
  @Mock
  TokenUtils tokenUtils;

  @InjectMocks
  IamUserInfoEndpoint controller;

  @Mock
  OAuth2Authentication auth;
  @Mock
  OAuth2Request oAuth2Request;

  @Test
  void shouldThrowAuthExceptionWhenAccountNotFound() {

    String username = "test-user";

    when(auth.getName()).thenReturn(username);
    when(auth.getOAuth2Request()).thenReturn(oAuth2Request);
    when(accountRepo.findByUsername(username)).thenReturn(Optional.empty());

    AuthException ex = assertThrows(AuthException.class, () -> {
      controller.getInfo(auth);
    });

    assertEquals("Account id not found", ex.getMessage());
  }

  @Test
  void shouldThrowAuthExceptionWhenClientNotFound() {

    String username = "test-user";
    String clientId = "client-123";

    IamAccount account = new IamAccount();

    when(auth.getName()).thenReturn(username);
    when(auth.getOAuth2Request()).thenReturn(oAuth2Request);
    when(oAuth2Request.getClientId()).thenReturn(clientId);

    when(accountRepo.findByUsername(username)).thenReturn(Optional.of(account));
    when(clientRepo.findByClientId(clientId)).thenReturn(Optional.empty());

    AuthException ex = assertThrows(AuthException.class, () -> {
      controller.getInfo(auth);
    });

    assertEquals("Client id not found", ex.getMessage());
  }
}
