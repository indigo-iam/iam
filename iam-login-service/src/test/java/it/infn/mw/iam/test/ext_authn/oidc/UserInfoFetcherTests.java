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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mitre.openid.connect.model.UserInfo;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.JsonObject;

import it.infn.mw.iam.authn.oidc.OIDCProviderMetadata;
import it.infn.mw.iam.authn.oidc.PendingOIDCAuthenticationToken;
import it.infn.mw.iam.authn.oidc.RestTemplateFactory;
import it.infn.mw.iam.authn.oidc.service.UserInfoFetcher;

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
    when(token.getSub()).thenReturn(SUB);
  }

  @Test
  void testLoadUserInfoReturnsParsedUserInfo() {

    OIDCProviderMetadata metadata =
        new OIDCProviderMetadata(ISSUER, ISSUER + "/authorize", ISSUER + "/token", ISSUER + "/jwks",
            USERINFO_ENDPOINT, new ObjectMapper().createObjectNode());

    when(token.getWellKnownEndpoint()).thenReturn(metadata);
    when(token.getCredentials()).thenReturn("access-token");
    when(restTemplateFactory.newRestTemplate()).thenReturn(restTemplate);

    JsonObject userInfoJson = new JsonObject();
    userInfoJson.addProperty("sub", SUB);
    when(restTemplate.getForObject(USERINFO_ENDPOINT, String.class))
      .thenReturn(userInfoJson.toString());

    UserInfo result = userInfoFetcher.loadUserInfo(token);

    assertNotNull(result);
    assertEquals(SUB, result.getSub());
    verify(restTemplate).getForObject(USERINFO_ENDPOINT, String.class);
  }

  @Test
  void testNullMetadataReturnsNull() {

    when(token.getWellKnownEndpoint()).thenReturn(null);

    UserInfo userInfo = userInfoFetcher.loadUserInfo(token);

    assertNull(userInfo);
    verifyNoInteractions(restTemplateFactory);
    verifyNoInteractions(restTemplate);
  }

  @Test
  void testNullUserInfoEndpointReturnsNull() {

    OIDCProviderMetadata metadata = new OIDCProviderMetadata(ISSUER, ISSUER + "/authorize",
        ISSUER + "/token", ISSUER + "/jwks", null, new ObjectMapper().createObjectNode());

    when(token.getWellKnownEndpoint()).thenReturn(metadata);

    UserInfo result = userInfoFetcher.loadUserInfo(token);

    assertNull(result);
    verifyNoInteractions(restTemplateFactory);
    verifyNoInteractions(restTemplate);
  }

  @Test
  void testEmptyUserInfoEndpointReturnsNull() {


    OIDCProviderMetadata emptyMetadata = new OIDCProviderMetadata(ISSUER, ISSUER + "/authorize",
        ISSUER + "/token", ISSUER + "/jwks", "", new ObjectMapper().createObjectNode());

    when(token.getWellKnownEndpoint()).thenReturn(emptyMetadata);

    UserInfo userInfo = userInfoFetcher.loadUserInfo(token);

    assertNull(userInfo);
    verifyNoInteractions(restTemplateFactory);
    verifyNoInteractions(restTemplate);
  }

  @Test
  void testEmptyResponseThrowsException() {

    OIDCProviderMetadata metadata =
        new OIDCProviderMetadata(ISSUER, ISSUER + "/authorize", ISSUER + "/token", ISSUER + "/jwks",
            USERINFO_ENDPOINT, new ObjectMapper().createObjectNode());

    when(restTemplateFactory.newRestTemplate()).thenReturn(restTemplate);
    when(token.getWellKnownEndpoint()).thenReturn(metadata);
    when(token.getCredentials()).thenReturn("access-token");
    when(restTemplate.getForObject(USERINFO_ENDPOINT, String.class)).thenReturn("");

    assertThrows(IllegalArgumentException.class, () -> userInfoFetcher.loadUserInfo(token));
  }

  @Test
  void testNullResponseThrowsException() {

    OIDCProviderMetadata metadata =
        new OIDCProviderMetadata(ISSUER, ISSUER + "/authorize", ISSUER + "/token", ISSUER + "/jwks",
            USERINFO_ENDPOINT, new ObjectMapper().createObjectNode());

    when(restTemplateFactory.newRestTemplate()).thenReturn(restTemplate);
    when(token.getWellKnownEndpoint()).thenReturn(metadata);
    when(token.getCredentials()).thenReturn("access-token");
    when(restTemplate.getForObject(USERINFO_ENDPOINT, String.class)).thenReturn(null);

    assertThrows(IllegalArgumentException.class, () -> userInfoFetcher.loadUserInfo(token));
  }
}
