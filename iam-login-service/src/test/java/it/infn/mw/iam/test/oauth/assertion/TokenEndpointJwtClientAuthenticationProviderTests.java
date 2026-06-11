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
package it.infn.mw.iam.test.oauth.assertion;

import static java.util.Collections.singletonList;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mitre.jwt.signer.service.impl.ClientKeyCacheService;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.ClientDetailsEntity.AuthMethod;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.beust.jcommander.internal.Lists;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.assertion.JwtAssertionAuthenticationToken;
import it.infn.mw.iam.core.oauth.assertion.TokenEndpointJwtClientAuthenticationProvider;

@ExtendWith(MockitoExtension.class)
class TokenEndpointJwtClientAuthenticationProviderTests
    implements TokenEndpointJwtClientAuthenticationProviderTestSupport {

  static final Instant NOW = Instant.parse("2021-01-01T00:00:00.00Z");

  @Mock
  ClientService clientService;

  @Mock
  ClientKeyCacheService validators;

  @Mock
  IamProperties iamProperties;

  @Mock
  JwtAssertionAuthenticationToken authentication;

  @Mock
  JWTSigningAndValidationService validator;

  @Mock
  ClientDetailsEntity client;

  TokenEndpointJwtClientAuthenticationProvider provider;

  Clock clock = Clock.fixed(NOW, ZoneId.of("UTC"));

  RSAKey rsaJwk;

  @BeforeEach
  void setup() throws JOSEException {

    lenient().when(authentication.getName()).thenReturn(JWT_AUTH_NAME);
    lenient().when(iamProperties.getIssuer()).thenReturn(ISSUER);
    lenient().when(clientService.findClientByClientId(JWT_AUTH_NAME))
      .thenReturn(Optional.of(client));
    lenient().when(client.getClientId()).thenReturn(JWT_AUTH_NAME);
    lenient().when(validators.getValidator(Mockito.any(), Mockito.any())).thenReturn(validator);
    lenient().when(validator.validateSignature(Mockito.any())).thenReturn(true);

    provider = new TokenEndpointJwtClientAuthenticationProvider(clock, iamProperties, clientService,
        validators);
    rsaJwk = new RSAKeyGenerator(2048).keyID("test-key").generate();
  }

  @Test
  void testClientNotFoundTriggersUsernameNotFoundException() {

    lenient().when(clientService.findClientByClientId(JWT_AUTH_NAME)).thenReturn(Optional.empty());

    UsernameNotFoundException e =
        assertThrows(UsernameNotFoundException.class, () -> provider.authenticate(authentication));
    assertThat(e.getMessage(), containsString("Client not found"));
  }

  @Test
  void testNullJwtTriggersException() {

    AuthenticationServiceException e = assertThrows(AuthenticationServiceException.class,
        () -> provider.authenticate(authentication));
    assertThat(e.getMessage(), containsString("Null JWT"));
  }

  @Test
  void testUnsupportClientAuthMethodTriggersException() throws JOSEException {

    lenient().when(authentication.getCredentials()).thenReturn(macSignJwt(JUST_SUB_JWT));

    List<AuthMethod> authMethod =
        Lists.newArrayList(null, AuthMethod.NONE, AuthMethod.SECRET_BASIC, AuthMethod.SECRET_POST);

    for (AuthMethod am : authMethod) {
      lenient().when(client.getTokenEndpointAuthMethod()).thenReturn(am);

      try {
        provider.authenticate(authentication);
      } catch (AuthenticationServiceException e) {
        assertThat(e.getMessage(),
            containsString("Client does not support JWT-based client autentication"));
      }
    }

  }

  @Test
  void testInvalidAsymmetricAlgo() {

    lenient().when(client.getTokenEndpointAuthMethod()).thenReturn(AuthMethod.SECRET_JWT);

    JWSAlgorithm.Family.SIGNATURE.forEach(a -> {
      SignedJWT jws = new SignedJWT(new JWSHeader(a), JUST_SUB_JWT);
      lenient().when(authentication.getCredentials()).thenReturn(jws);

      try {
        provider.authenticate(authentication);
      } catch (AuthenticationServiceException e) {
        assertThat(e.getMessage(), containsString("Invalid signature algorithm: " + a.getName()));
      }
    });
  }

  @Test
  void testInvalidSymmetricAlgo() {

    lenient().when(client.getTokenEndpointAuthMethod()).thenReturn(AuthMethod.PRIVATE_KEY);

    JWSAlgorithm.Family.HMAC_SHA.forEach(a -> {
      SignedJWT jws = new SignedJWT(new JWSHeader(a), JUST_SUB_JWT);
      lenient().when(authentication.getCredentials()).thenReturn(jws);

      try {
        provider.authenticate(authentication);
      } catch (AuthenticationServiceException e) {
        assertThat(e.getMessage(), containsString("Invalid signature algorithm: " + a.getName()));
      }
    });

  }

  @Test
  void testInvalidAlgo() {

    lenient().when(client.getTokenEndpointAuthMethod()).thenReturn(AuthMethod.PRIVATE_KEY);
    lenient().when(client.getTokenEndpointAuthSigningAlg()).thenReturn(JWSAlgorithm.RS256);

    SignedJWT jws = new SignedJWT(new JWSHeader(JWSAlgorithm.RS384), JUST_SUB_JWT);
    lenient().when(authentication.getCredentials()).thenReturn(jws);

    try {
      provider.authenticate(authentication);
    } catch (AuthenticationServiceException e) {
      assertThat(e.getMessage(), containsString("Invalid signature algorithm: RS384"));
    }

    jws = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), JUST_SUB_JWT);
    lenient().when(authentication.getCredentials()).thenReturn(jws);

    try {
      provider.authenticate(authentication);
    } catch (AuthenticationServiceException e) {
      assertThat(e.getMessage(), containsString("Invalid signature algorithm: HS256"));
    }

    lenient().when(client.getTokenEndpointAuthMethod()).thenReturn(AuthMethod.SECRET_JWT);
    lenient().when(client.getTokenEndpointAuthSigningAlg()).thenReturn(JWSAlgorithm.HS256);

    jws = new SignedJWT(new JWSHeader(JWSAlgorithm.HS384), JUST_SUB_JWT);
    lenient().when(authentication.getCredentials()).thenReturn(jws);

    try {
      provider.authenticate(authentication);
    } catch (AuthenticationServiceException e) {
      assertThat(e.getMessage(), containsString("Invalid signature algorithm: HS384"));
    }

    jws = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), JUST_SUB_JWT);
    lenient().when(authentication.getCredentials()).thenReturn(jws);

    try {
      provider.authenticate(authentication);
    } catch (AuthenticationServiceException e) {
      assertThat(e.getMessage(), containsString("Invalid signature algorithm: RS256"));
    }

  }

  @Test
  void testValidatorNotFound() {

    lenient().when(validators.getValidator(Mockito.any(), Mockito.any())).thenReturn(null);

    testForAllAlgos(client, a -> {
      SignedJWT jws = new SignedJWT(new JWSHeader(a), JUST_SUB_JWT);
      lenient().when(authentication.getCredentials()).thenReturn(jws);

      try {
        provider.authenticate(authentication);
      } catch (AuthenticationServiceException e) {
        assertThat(e.getMessage(), containsString("Unable to resolve validator"));
        assertThat(e.getMessage(), containsString(JWT_AUTH_NAME));
        assertThat(e.getMessage(), containsString(a.getName()));
      }
    });
  }

  @Test
  void testInvalidSignatureHandled() {

    lenient().when(validators.getValidator(Mockito.any(), Mockito.any())).thenReturn(validator);
    lenient().when(validator.validateSignature(Mockito.any())).thenReturn(false);

    lenient().when(client.getTokenEndpointAuthMethod()).thenReturn(AuthMethod.SECRET_JWT);

    JWSAlgorithm.Family.HMAC_SHA.forEach(a -> {
      SignedJWT jws = new SignedJWT(new JWSHeader(a), JUST_SUB_JWT);
      lenient().when(authentication.getCredentials()).thenReturn(jws);

      try {
        provider.authenticate(authentication);
      } catch (AuthenticationServiceException e) {
        assertThat(e.getMessage(), containsString("invalid signature"));
      }
    });

    lenient().when(client.getTokenEndpointAuthMethod()).thenReturn(AuthMethod.PRIVATE_KEY);

    JWSAlgorithm.Family.SIGNATURE.forEach(a -> {
      SignedJWT jws = new SignedJWT(new JWSHeader(a), JUST_SUB_JWT);
      lenient().when(authentication.getCredentials()).thenReturn(jws);

      try {
        provider.authenticate(authentication);
      } catch (AuthenticationServiceException e) {
        assertThat(e.getMessage(), containsString("invalid signature"));
      }
    });
  }

  @Test
  void testInvalidAssertionIssuer() {

    lenient().when(validators.getValidator(Mockito.any(), Mockito.any())).thenReturn(validator);
    lenient().when(validator.validateSignature(Mockito.any())).thenReturn(true);

    testForAllAlgos(client, a -> {

      JWSHeader header = new JWSHeader(a);
      SignedJWT jws = new SignedJWT(header, JUST_SUB_JWT);
      lenient().when(authentication.getCredentials()).thenReturn(jws);

      try {
        provider.authenticate(authentication);
      } catch (AuthenticationServiceException e) {
        assertThat(e.getMessage(), containsString("issuer is null"));
      }

      JWTClaimsSet claimSet =
          new JWTClaimsSet.Builder().issuer("invalid-issuer").subject(JWT_AUTH_NAME).build();

      jws = new SignedJWT(header, claimSet);
      lenient().when(authentication.getCredentials()).thenReturn(jws);

      try {
        provider.authenticate(authentication);
      } catch (AuthenticationServiceException e) {
        assertThat(e.getMessage(), containsString("issuer does not match client id"));
      }
    });
  }

  @Test
  void testExpirationTimeNotSet() {

    lenient().when(validators.getValidator(Mockito.any(), Mockito.any())).thenReturn(validator);
    lenient().when(validator.validateSignature(Mockito.any())).thenReturn(true);

    testForAllAlgos(client, a -> {
      JWSHeader header = new JWSHeader(a);
      JWTClaimsSet claimSet =
          new JWTClaimsSet.Builder().issuer(JWT_AUTH_NAME).subject(JWT_AUTH_NAME).build();
      SignedJWT jws = new SignedJWT(header, claimSet);
      lenient().when(authentication.getCredentials()).thenReturn(jws);

      try {
        provider.authenticate(authentication);
      } catch (AuthenticationServiceException e) {
        assertThat(e.getMessage(), containsString("expiration time not set"));
      }
    });
  }

  @Test
  void testExpirationInThePast() {

    lenient().when(validators.getValidator(Mockito.any(), Mockito.any())).thenReturn(validator);
    lenient().when(validator.validateSignature(Mockito.any())).thenReturn(true);

    testForAllAlgos(client, a -> {
      JWSHeader header = new JWSHeader(a);
      JWTClaimsSet claimSet = new JWTClaimsSet.Builder().issuer(JWT_AUTH_NAME)
        .subject(JWT_AUTH_NAME)
        .expirationTime(Date.from(clock.instant().minusSeconds(301)))
        .build();
      SignedJWT jws = new SignedJWT(header, claimSet);
      lenient().when(authentication.getCredentials()).thenReturn(jws);

      try {
        provider.authenticate(authentication);
      } catch (AuthenticationServiceException e) {
        assertThat(e.getMessage(), containsString("expired assertion token"));
      }
    });
  }

  @Test
  void testNotBeforeInTheFuture() {

    lenient().when(validators.getValidator(Mockito.any(), Mockito.any())).thenReturn(validator);
    lenient().when(validator.validateSignature(Mockito.any())).thenReturn(true);

    testForAllAlgos(client, a -> {
      JWSHeader header = new JWSHeader(a);
      JWTClaimsSet claimSet = new JWTClaimsSet.Builder().issuer(JWT_AUTH_NAME)
        .subject(JWT_AUTH_NAME)
        .expirationTime(Date.from(clock.instant().plusSeconds(1800)))
        .notBeforeTime(Date.from(clock.instant().plusSeconds(900)))
        .build();
      SignedJWT jws = new SignedJWT(header, claimSet);
      lenient().when(authentication.getCredentials()).thenReturn(jws);

      try {
        provider.authenticate(authentication);
      } catch (AuthenticationServiceException e) {
        assertThat(e.getMessage(), containsString("assertion is not yet valid"));
      }
    });
  }

  @Test
  void testIssuedInTheFuture() {

    lenient().when(validators.getValidator(Mockito.any(), Mockito.any())).thenReturn(validator);
    lenient().when(validator.validateSignature(Mockito.any())).thenReturn(true);

    testForAllAlgos(client, a -> {
      JWSHeader header = new JWSHeader(a);
      JWTClaimsSet claimSet = new JWTClaimsSet.Builder().issuer(JWT_AUTH_NAME)
        .subject(JWT_AUTH_NAME)
        .expirationTime(Date.from(clock.instant().plusSeconds(1800)))
        .issueTime(Date.from(clock.instant().plusSeconds(1000)))
        .build();
      SignedJWT jws = new SignedJWT(header, claimSet);
      lenient().when(authentication.getCredentials()).thenReturn(jws);

      try {
        provider.authenticate(authentication);
      } catch (AuthenticationServiceException e) {
        assertThat(e.getMessage(), containsString("assertion was issued in the future"));
      }
    });
  }

  @Test
  void testNullAudience() {

    lenient().when(validators.getValidator(Mockito.any(), Mockito.any())).thenReturn(validator);
    lenient().when(validator.validateSignature(Mockito.any())).thenReturn(true);

    testForAllAlgos(client, a -> {
      JWSHeader header = new JWSHeader(a);
      JWTClaimsSet claimSet = new JWTClaimsSet.Builder().issuer(JWT_AUTH_NAME)
        .subject(JWT_AUTH_NAME)
        .expirationTime(Date.from(clock.instant().plusSeconds(1800)))
        .build();
      SignedJWT jws = new SignedJWT(header, claimSet);
      lenient().when(authentication.getCredentials()).thenReturn(jws);

      try {
        provider.authenticate(authentication);
      } catch (AuthenticationServiceException e) {
        assertThat(e.getMessage(), containsString("invalid audience"));
      }
    });
  }

  @Test
  void testInvalidAudience() {

    lenient().when(validators.getValidator(Mockito.any(), Mockito.any())).thenReturn(validator);
    lenient().when(validator.validateSignature(Mockito.any())).thenReturn(true);

    testForAllAlgos(client, a -> {
      JWSHeader header = new JWSHeader(a);
      JWTClaimsSet claimSet = new JWTClaimsSet.Builder().issuer(JWT_AUTH_NAME)
        .subject(JWT_AUTH_NAME)
        .expirationTime(Date.from(clock.instant().plusSeconds(1800)))
        .audience(singletonList("invalid-audience"))
        .build();
      SignedJWT jws = new SignedJWT(header, claimSet);
      lenient().when(authentication.getCredentials()).thenReturn(jws);

      try {
        provider.authenticate(authentication);
      } catch (AuthenticationServiceException e) {
        assertThat(e.getMessage(), containsString("invalid audience"));
      }
    });
  }

  @Test
  void testJTIRequired() {

    lenient().when(validators.getValidator(Mockito.any(), Mockito.any())).thenReturn(validator);
    lenient().when(validator.validateSignature(Mockito.any())).thenReturn(true);

    testForAllAlgos(client, a -> {
      JWSHeader header = new JWSHeader(a);
      JWTClaimsSet claimSet = new JWTClaimsSet.Builder().issuer(JWT_AUTH_NAME)
        .subject(JWT_AUTH_NAME)
        .expirationTime(Date.from(clock.instant().plusSeconds(1800)))
        .audience(singletonList(ISSUER_TOKEN_ENDPOINT))
        .build();
      SignedJWT jws = new SignedJWT(header, claimSet);
      lenient().when(authentication.getCredentials()).thenReturn(jws);

      try {
        provider.authenticate(authentication);
      } catch (AuthenticationServiceException e) {
        assertThat(e.getMessage(), containsString("jti is null"));
      }
    });
  }

  @Test
  void testValidAssertion() {

    lenient().when(validators.getValidator(Mockito.any(), Mockito.any())).thenReturn(validator);
    lenient().when(validator.validateSignature(Mockito.any())).thenReturn(true);

    testForAllAlgos(client, a -> {
      JWSHeader header = new JWSHeader(a);
      JWTClaimsSet claimSet = new JWTClaimsSet.Builder().issuer(JWT_AUTH_NAME)
        .subject(JWT_AUTH_NAME)
        .expirationTime(Date.from(clock.instant().plusSeconds(1800)))
        .audience(singletonList(ISSUER_TOKEN_ENDPOINT))
        .jwtID(UUID.randomUUID().toString())
        .build();
      SignedJWT jws = new SignedJWT(header, claimSet);
      lenient().when(authentication.getCredentials()).thenReturn(jws);

      JwtAssertionAuthenticationToken authToken =
          (JwtAssertionAuthenticationToken) provider.authenticate(authentication);
      assertThat(authToken.isAuthenticated(), is(true));
      assertThat(authToken.getName(), is(JWT_AUTH_NAME));
      assertThat(authToken.getAuthorities(), hasItem(ROLE_CLIENT_AUTHORITY));
      assertThat(authToken.getAuthorities(), hasSize(1));
    });
  }

  @Test
  void testEqualAssertions() throws JOSEException {

    lenient().when(validators.getValidator(Mockito.any(), Mockito.any())).thenReturn(validator);
    lenient().when(validator.validateSignature(Mockito.any())).thenReturn(true);
    lenient().when(client.getTokenEndpointAuthMethod()).thenReturn(AuthMethod.PRIVATE_KEY);

    Date date = Date.from(clock.instant().plusSeconds(1800));
    String uuid = UUID.randomUUID().toString();

    JwtAssertionAuthenticationToken authTokenEq1 =
        buildJwtAssertionAsymmetricAuthenticationToken(date, uuid);
    JwtAssertionAuthenticationToken authTokenEq2 =
        buildJwtAssertionAsymmetricAuthenticationToken(date, uuid);
    JwtAssertionAuthenticationToken authTokenNotEq =
        buildJwtAssertionAsymmetricAuthenticationToken(date, UUID.randomUUID().toString());

    assertTrue(authTokenEq1.equals(authTokenEq1));
    assertTrue(authTokenEq1.equals(authTokenEq2));
    assertFalse(authTokenEq1.equals(authTokenNotEq));
    assertEquals(authTokenEq1.hashCode(), authTokenEq2.hashCode());

  }

  private JwtAssertionAuthenticationToken buildJwtAssertionAsymmetricAuthenticationToken(Date date,
      String uuid) throws JOSEException {

    JWTClaimsSet claimSet = new JWTClaimsSet.Builder().issuer(JWT_AUTH_NAME)
      .subject(JWT_AUTH_NAME)
      .expirationTime(date)
      .audience(singletonList(ISSUER_TOKEN_ENDPOINT))
      .jwtID(uuid)
      .build();

    JWSAlgorithm a = JWSAlgorithm.RS256;
    JWSHeader header = new JWSHeader(a);

    SignedJWT jws = new SignedJWT(header, claimSet);
    jws.sign(new RSASSASigner(rsaJwk.toPrivateKey()));
    lenient().when(authentication.getCredentials()).thenReturn(jws);
    return (JwtAssertionAuthenticationToken) provider.authenticate(authentication);
  }

}
