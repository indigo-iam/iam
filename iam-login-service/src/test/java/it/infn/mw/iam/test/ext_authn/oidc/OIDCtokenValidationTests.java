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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.util.Date;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mitre.jwt.signer.service.impl.JWKSetCacheService;
import org.mitre.openid.connect.client.service.IssuerService;
import org.mockito.Mock;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationServiceException;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;

import it.infn.mw.iam.authn.oidc.OIDCAuthenticationFilter;
import it.infn.mw.iam.authn.oidc.OidcTokenRequestor;
import it.infn.mw.iam.authn.oidc.PlainAuthRequestUrlBuilder;
import it.infn.mw.iam.authn.oidc.service.OIDCProviderMetadataService;
import it.infn.mw.iam.config.oidc.OidcProviderProperties;

public class OIDCtokenValidationTests {

  @Mock
  private JWKSetCacheService validationServices;

  @Mock
  private IssuerService issuerService;

  @Mock
  private OIDCProviderMetadataService servers;

  @Mock
  private OidcProviderProperties clients;

  @Mock
  private PlainAuthRequestUrlBuilder authRequestBuilder;

  @Mock
  private Clock clock;

  @Mock
  private OidcTokenRequestor tokenRequestor;

  @Mock
  private Environment env;

  @Mock
  private ObjectMapper objectMapper;

  private OIDCAuthenticationFilter filter;

  private static final String ISSUER = "https://test.example";
  private static final String CLIENT_ID = "client";

  @BeforeEach
  void setUp() {
    clock = Clock.systemUTC();

    filter = new OIDCAuthenticationFilter(validationServices, issuerService, servers, clients,
        authRequestBuilder, clock, tokenRequestor, env, new ObjectMapper(), 60);
    assertNotNull(filter);
  }

  @Test
  void testThrowExceptionWhenTokenIssuerIsNull() {

    JWTClaimsSet claims =
        new JWTClaimsSet.Builder().expirationTime(Date.from(clock.instant().plusSeconds(100)))
          .build();

    AuthenticationServiceException ex = assertThrows(AuthenticationServiceException.class,
        () -> filter.validateClaims(claims, ISSUER, CLIENT_ID));
    assertEquals("Issuer claim not present in the ID token", ex.getMessage());
  }

  @Test
  void testThrowExceptionWhenTokenIssuerDoesNotMatch() {

    JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer("https://wrong-issuer.example")
      .expirationTime(Date.from(clock.instant().plusSeconds(100)))
      .build();

    AuthenticationServiceException ex = assertThrows(AuthenticationServiceException.class,
        () -> filter.validateClaims(claims, "https://expected.example", CLIENT_ID));
    assertTrue(
        ex.getMessage().contains("ID token issuer claim does not match the client configuration"));
  }

  @Test
  void testThrowExceptionWhenExpirationIsMissing() {

    JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(ISSUER).build();

    AuthenticationServiceException ex = assertThrows(AuthenticationServiceException.class,
        () -> filter.validateClaims(claims, ISSUER, CLIENT_ID));
    assertEquals("ID Token does not have required expiration claim", ex.getMessage());
  }

  @Test
  void testThrowExceptionWhenTokenIsExpired() {

    JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(ISSUER)
      .expirationTime(Date.from(clock.instant().minusSeconds(100)))
      .build();

    AuthenticationServiceException ex = assertThrows(AuthenticationServiceException.class,
        () -> filter.validateClaims(claims, ISSUER, CLIENT_ID));
    assertTrue(ex.getMessage().contains("ID Token is expired"));
  }

  @Test
  void testThrowExceptionWhenNotBeforeIsInFuture() {

    JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(ISSUER)
      .expirationTime(Date.from(clock.instant().plusSeconds(3600)))
      .issueTime(Date.from(clock.instant()))
      .notBeforeTime(Date.from(clock.instant().plusSeconds(100)))
      .audience("client")
      .build();

    AuthenticationServiceException ex = assertThrows(AuthenticationServiceException.class,
        () -> filter.validateClaims(claims, ISSUER, CLIENT_ID));
    assertTrue(ex.getMessage().contains("ID Token not valid until"));
  }

  @Test
  void testThrowExceptionWhenIssuedAtMissing() {

    JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(ISSUER)
      .expirationTime(Date.from(clock.instant().plusSeconds(100)))
      .build();

    AuthenticationServiceException ex = assertThrows(AuthenticationServiceException.class,
        () -> filter.validateClaims(claims, ISSUER, CLIENT_ID));

    assertEquals("ID Token does not have required issued-at claim", ex.getMessage());
  }

  @Test
  void testThrowExceptionWhenAudienceIsEmpty() {

    JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(ISSUER)
      .expirationTime(Date.from(clock.instant().plusSeconds(100)))
      .issueTime(Date.from(clock.instant()))
      .build();

    AuthenticationServiceException ex = assertThrows(AuthenticationServiceException.class,
        () -> filter.validateClaims(claims, ISSUER, CLIENT_ID));

    assertEquals("Audience claim not present in the ID token", ex.getMessage());
  }

  @Test
  void testThrowExceptionWhenAudienceDoesNotContainClientId() {

    JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(ISSUER)
      .expirationTime(Date.from(clock.instant().plusSeconds(100)))
      .issueTime(Date.from(clock.instant()))
      .audience("other-client")
      .build();

    AuthenticationServiceException ex = assertThrows(AuthenticationServiceException.class,
        () -> filter.validateClaims(claims, ISSUER, CLIENT_ID));
    assertTrue(ex.getMessage()
      .contains("ID token audience claim does not match the client configuration"));
  }

}
