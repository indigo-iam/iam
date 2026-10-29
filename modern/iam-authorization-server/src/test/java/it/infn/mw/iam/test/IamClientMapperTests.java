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
package it.infn.mw.iam.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import com.nimbusds.jose.JWSAlgorithm;

import it.infn.mw.iam.core.IamClientMapper;
import it.infn.mw.iam.persistence.client.model.ClientAuthMethod;
import it.infn.mw.iam.persistence.client.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.client.model.PKCEAlgorithm;

class IamClientMapperTests {

  private final IamClientMapper mapper = new IamClientMapper();

  @Test
  void shouldMapClientDetailsEntityToRegisteredClient() {
    ClientDetailsEntity client = new ClientDetailsEntity();

    client.setId(123L);
    client.setClientId("test-client");
    client.setClientSecret("secret");
    client.setClientName("Test Client");

    client.setGrantTypes(Set.of("authorization_code", "refresh_token"));
    client.setRedirectUris(Set.of("https://example.org/callback"));
    client.setScope(Set.of("openid", "profile"));

    client.setTokenEndpointAuthMethod(ClientAuthMethod.SECRET_BASIC);
    client.setCodeChallengeMethod(PKCEAlgorithm.S256);

    client.setJwksUri("https://example.org/jwks");
    client.setPostLogoutRedirectUris(Set.of("https://example.org/logout"));

    client.setAccessTokenValiditySeconds(600);
    client.setRefreshTokenValiditySeconds(3600);
    client.setReuseRefreshToken(false);

    client.setTokenEndpointAuthSigningAlg(JWSAlgorithm.RS256);

    RegisteredClient result = mapper.toRegisteredClient(client);

    assertEquals("123", result.getId());
    assertEquals("test-client", result.getClientId());
    assertEquals("secret", result.getClientSecret());
    assertEquals("Test Client", result.getClientName());

    assertEquals(
        Set.of(AuthorizationGrantType.AUTHORIZATION_CODE, AuthorizationGrantType.REFRESH_TOKEN),
        result.getAuthorizationGrantTypes());

    assertEquals(Set.of("https://example.org/callback"), result.getRedirectUris());

    assertEquals(Set.of("openid", "profile"), result.getScopes());

    assertEquals(Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC),
        result.getClientAuthenticationMethods());

    assertTrue(result.getClientSettings().isRequireProofKey());
    assertEquals("https://example.org/jwks", result.getClientSettings().getJwkSetUrl());

    assertEquals(SignatureAlgorithm.RS256,
        result.getClientSettings().getTokenEndpointAuthenticationSigningAlgorithm());

    assertEquals(Set.of("https://example.org/logout"), result.getPostLogoutRedirectUris());

    assertFalse(result.getTokenSettings().isReuseRefreshTokens());
    assertEquals(Duration.ofSeconds(600), result.getTokenSettings().getAccessTokenTimeToLive());
    assertEquals(Duration.ofSeconds(3600), result.getTokenSettings().getRefreshTokenTimeToLive());
  }

  @ParameterizedTest
  @EnumSource(value = PKCEAlgorithm.class, names = {"NONE", "OPTIONAL"})
  void shouldNotRequireProofKey(PKCEAlgorithm algorithm) {
    ClientDetailsEntity client = new ClientDetailsEntity();
    client.setId(1L);
    client.setClientId("client-without-pkce");
    client.setRedirectUris(Set.of("https://example.org/callback"));
    client.setGrantTypes(Set.of("authorization_code"));
    client.setTokenEndpointAuthMethod(ClientAuthMethod.NONE);
    client.setCodeChallengeMethod(algorithm);

    RegisteredClient result = mapper.toRegisteredClient(client);

    assertFalse(result.getClientSettings().isRequireProofKey());
  }
}
