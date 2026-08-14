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
package it.infn.mw.iam.test.ext_authn.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.client.RestTemplate;

import it.infn.mw.iam.authn.oidc.OIDCProviderMetadata;
import it.infn.mw.iam.authn.oidc.PendingOIDCAuthenticationToken;
import it.infn.mw.iam.authn.oidc.RestTemplateFactory;
import it.infn.mw.iam.authn.oidc.service.UserInfoFetcher;
import it.infn.mw.iam.core.userinfo.UserInfoResponse;

@ExtendWith(MockitoExtension.class)
class UserInfoFetcherTests {

  @Mock
  private RestTemplateFactory restTemplateFactory;

  @Mock
  private RestTemplate restTemplate;

  @Mock
  private PendingOIDCAuthenticationToken token;

  private UserInfoFetcher userInfoFetcher;

  private static final String SUB = "1234";
  private static final String ISSUER = "https://issuer.example";
  private static final String USERINFO_ENDPOINT = ISSUER + "/userinfo";

  @BeforeEach
  void setup() {

    userInfoFetcher = new UserInfoFetcher(restTemplateFactory);
  }

  @Test
  void testLoadUserInfoReturnsParsedUserInfo() {

    OIDCProviderMetadata metadata = new OIDCProviderMetadata(ISSUER, ISSUER + "/authorize",
        ISSUER + "/token", ISSUER + "/jwks", USERINFO_ENDPOINT);

    when(token.getWellKnownEndpoint()).thenReturn(metadata);
    when(token.getCredentials()).thenReturn("access-token");
    when(restTemplateFactory.newRestTemplate()).thenReturn(restTemplate);

    UserInfoResponse response = new UserInfoResponse(Map.of("sub", SUB));
    when(restTemplate.getForObject(USERINFO_ENDPOINT, UserInfoResponse.class))
      .thenReturn(response);

    Optional<UserInfoResponse> userInfo = userInfoFetcher.loadUserInfo(token);

    assertTrue(userInfo.isPresent());
    assertEquals(SUB, userInfo.get().getSub());
    verify(restTemplate).getForObject(USERINFO_ENDPOINT, UserInfoResponse.class);
  }

  @Test
  void testNullMetadataReturnsEmptyUserInfo() {

    when(token.getWellKnownEndpoint()).thenReturn(null);

    Optional<UserInfoResponse> userInfo = userInfoFetcher.loadUserInfo(token);

    assertTrue(userInfo.isEmpty());
    verifyNoInteractions(restTemplateFactory);
    verifyNoInteractions(restTemplate);
  }

  @Test
  void testNullUserInfoEndpointReturnsEmptyUserInfo() {

    OIDCProviderMetadata metadata = new OIDCProviderMetadata(ISSUER, ISSUER + "/authorize",
        ISSUER + "/token", ISSUER + "/jwks", null);

    when(token.getWellKnownEndpoint()).thenReturn(metadata);

    Optional<UserInfoResponse> userInfo = userInfoFetcher.loadUserInfo(token);

    assertTrue(userInfo.isEmpty());
    verifyNoInteractions(restTemplateFactory);
    verifyNoInteractions(restTemplate);
  }

  @Test
  void testEmptyUserInfoEndpointReturnsEmptyUserInfo() {

    OIDCProviderMetadata emptyMetadata = new OIDCProviderMetadata(ISSUER, ISSUER + "/authorize",
        ISSUER + "/token", ISSUER + "/jwks", "");

    when(token.getWellKnownEndpoint()).thenReturn(emptyMetadata);

    Optional<UserInfoResponse> userInfo = userInfoFetcher.loadUserInfo(token);

    assertTrue(userInfo.isEmpty());
    verifyNoInteractions(restTemplateFactory);
    verifyNoInteractions(restTemplate);
  }

  @Test
  void testNullResponseReturnsEmptyUserInfo() {

    OIDCProviderMetadata metadata = new OIDCProviderMetadata(ISSUER, ISSUER + "/authorize",
        ISSUER + "/token", ISSUER + "/jwks", USERINFO_ENDPOINT);

    when(restTemplateFactory.newRestTemplate()).thenReturn(restTemplate);
    when(token.getWellKnownEndpoint()).thenReturn(metadata);
    when(token.getCredentials()).thenReturn("access-token");
    when(restTemplate.getForObject(USERINFO_ENDPOINT, UserInfoResponse.class)).thenReturn(null);

    Optional<UserInfoResponse> userInfo = userInfoFetcher.loadUserInfo(token);
    assertTrue(userInfo.isEmpty());
  }
}
