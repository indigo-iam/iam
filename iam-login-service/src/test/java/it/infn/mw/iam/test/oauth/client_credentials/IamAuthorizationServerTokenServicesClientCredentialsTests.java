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
package it.infn.mw.iam.test.oauth.client_credentials;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anySet;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.IamAuthenticationHolderService;
import it.infn.mw.iam.core.TokenUtils;
import it.infn.mw.iam.core.as.IamAuthorizationServerTokenServices;
import it.infn.mw.iam.core.jwk.JWTSigningAndValidationService;
import it.infn.mw.iam.core.oauth.profile.JWTProfile;
import it.infn.mw.iam.core.oauth.profile.JWTProfileResolver;
import it.infn.mw.iam.core.oauth.profile.common.BaseAccessTokenBuilder;
import it.infn.mw.iam.core.oauth.revocation.TokenRevocationService;
import it.infn.mw.iam.core.oauth.scope.SystemScopeService;
import it.infn.mw.iam.core.oauth.scope.pdp.ScopeFilter;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.AuthenticationHolderEntity;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.model.OAuth2AccessTokenEntity;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;

@SuppressWarnings("deprecation")
@ExtendWith(MockitoExtension.class)
class IamAuthorizationServerTokenServicesClientCredentialsTests {

  static final String CLIENT_ID = "test-client";

  IamProperties iamProperties;

  @Mock
  IamOAuthAccessTokenRepository accessTokenRepo;

  @Mock
  IamOAuthRefreshTokenRepository refreshTokenRepo;

  @Mock
  IamAuthenticationHolderService authenticationHolderService;

  @Mock
  ClientService clientService;

  @Mock
  IamAccountService accountService;

  @Mock
  JWTSigningAndValidationService jwtSigningService;

  @Mock
  TokenRevocationService revocationService;

  @Mock
  SystemScopeService scopeService;

  @Mock
  JWTProfileResolver profileResolver;

  @Mock
  ApplicationEventPublisher eventPublisher;

  @Mock
  ScopeFilter scopeFilter;

  @Mock
  TokenUtils tokenUtils;

  @Mock
  ClientDetailsEntity client;

  @Mock
  AuthenticationHolderEntity authenticationHolder;

  @Mock
  JWTProfile jwtProfile;

  @Mock
  BaseAccessTokenBuilder accessTokenBuilder;

  IamAuthorizationServerTokenServices tokenServices;

  @BeforeEach
  void setup() {

    iamProperties = new IamProperties();

    tokenServices = new IamAuthorizationServerTokenServices(Clock.systemUTC(), iamProperties,
        accessTokenRepo, refreshTokenRepo, authenticationHolderService, clientService,
        accountService, jwtSigningService, revocationService, scopeService, profileResolver,
        eventPublisher, scopeFilter, tokenUtils);

    when(clientService.findClientByClientId(CLIENT_ID)).thenReturn(Optional.of(client));

    when(client.isActive()).thenReturn(true);
    when(client.isAllowRefresh()).thenReturn(true);

    when(authenticationHolderService.create(any(), eq(client))).thenReturn(authenticationHolder);

    when(scopeFilter.filterScopes(anySet(), any(OAuth2Authentication.class), CLIENT_ID))
      .thenAnswer(invocation -> invocation.getArgument(0));

    when(profileResolver.resolveProfile(anySet())).thenReturn(jwtProfile);

    when(jwtProfile.getAccessTokenBuilder()).thenReturn(accessTokenBuilder);

    when(jwtSigningService.getDefaultSigningAlgorithm()).thenReturn(JWSAlgorithm.HS256);

    when(jwtSigningService.getDefaultSignerKeyId()).thenReturn("test-key");

    byte[] secret = new byte[32];

    doAnswer(invocation -> {
      SignedJWT jwt = invocation.getArgument(0);
      jwt.sign(new MACSigner(secret));
      return null;
    }).when(jwtSigningService).signJwt(any(SignedJWT.class));

    JWTClaimsSet claims =
        new JWTClaimsSet.Builder().subject("test").issuer("https://issuer.example").build();

    when(accessTokenBuilder.buildAccessToken(any(OAuth2AccessTokenEntity.class),
        any(OAuth2Authentication.class), eq(Optional.empty()), any(Instant.class)))
          .thenReturn(claims);
  }

  @Test
  void shouldNotIssueRefreshTokenForClientCredentialsWithOfflineAccess() {

    OAuth2Request request = new OAuth2Request(Map.of("grant_type", "client_credentials"), CLIENT_ID,
        null, true, Set.of(SystemScopeService.OFFLINE_ACCESS_SCOPE), null, null, null, null);

    OAuth2Authentication authentication = new OAuth2Authentication(request, null);

    when(authenticationHolder.getAuthentication()).thenReturn(authentication);

    OAuth2AccessToken token = tokenServices.createAccessToken(authentication);

    assertThat(token.getRefreshToken()).isNull();

    verify(refreshTokenRepo, never()).save(any());
  }
}
