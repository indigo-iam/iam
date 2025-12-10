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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.lenient;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Date;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mitre.jwt.signer.service.impl.ClientKeyCacheService;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.ClientDetailsEntity.AuthMethod;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.openid.connect.assertion.JWTBearerAssertionAuthenticationToken;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.assertion.IAMJWTBearerAuthenticationProvider;

@ExtendWith(MockitoExtension.class)
class IAMJWTBearerAuthenticationProviderTests
    implements IAMJWTBearerAuthenticationProviderTestSupport {

  static final Instant NOW = Instant.parse("2021-01-01T00:00:00.00Z");

  @Mock
  ClientDetailsEntityService clientService;

  @Mock
  ClientKeyCacheService validators;

  @Mock
  IamProperties iamProperties;

  @Mock
  JWTBearerAssertionAuthenticationToken authentication;

  @Mock
  JWTSigningAndValidationService validator;

  @Mock
  ClientDetailsEntity client;

  IAMJWTBearerAuthenticationProvider provider;

  Clock clock = Clock.fixed(NOW, ZoneId.systemDefault());

  @BeforeEach
  void setup() {

    lenient().when(authentication.getName()).thenReturn(JWT_AUTH_NAME);
    lenient().when(iamProperties.getIssuer()).thenReturn(ISSUER);
    lenient().when(clientService.loadClientByClientId(JWT_AUTH_NAME)).thenReturn(client);
    lenient().when(client.getClientId()).thenReturn(JWT_AUTH_NAME);
    lenient().when(validators.getValidator(Mockito.any(), Mockito.any())).thenReturn(validator);
    lenient().when(validator.validateSignature(Mockito.any())).thenReturn(true);

    provider =
        new IAMJWTBearerAuthenticationProvider(clock, iamProperties, clientService, validators);
  }

  @Test
  void testClientNotFoundTriggersUsernameNotFoundException() {

    lenient().when(clientService.loadClientByClientId(JWT_AUTH_NAME)).thenReturn(null);

    UsernameNotFoundException e =
        assertThrows(UsernameNotFoundException.class, () -> provider.authenticate(authentication));
    assertThat(e.getMessage(), containsString("Unknown client"));
  }

  @Test
  void testPlainJwtTriggersException() {

    lenient().when(authentication.getJwt())
      .thenReturn(new PlainJWT(new JWTClaimsSet.Builder().subject("sub").build()));

    AuthenticationServiceException e = assertThrows(AuthenticationServiceException.class,
        () -> provider.authenticate(authentication));
    assertThat(e.getMessage(), containsString("Unsupported JWT type"));
  }

  @Test
  void testNullJwtTriggersException() {

    AuthenticationServiceException e = assertThrows(AuthenticationServiceException.class,
        () -> provider.authenticate(authentication));
    assertThat(e.getMessage(), containsString("Null JWT"));
  }

  @Test
  void testUnsupportClientAuthMethodTriggersException() throws JOSEException {

    lenient().when(authentication.getJwt()).thenReturn(macSignJwt(JUST_SUB_JWT));

    lenient().when(client.getTokenEndpointAuthMethod())
      .thenReturn(null, AuthMethod.NONE, AuthMethod.SECRET_BASIC, AuthMethod.SECRET_POST);

    for (int i = 0; i < 4; i++) {
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
      lenient().when(authentication.getJwt()).thenReturn(jws);

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
      lenient().when(authentication.getJwt()).thenReturn(jws);

      try {
        provider.authenticate(authentication);
      } catch (AuthenticationServiceException e) {
        assertThat(e.getMessage(), containsString("Invalid signature algorithm: " + a.getName()));
      }
    });

  }

  @Test
  void testValidatorNotFound() {

    lenient().when(validators.getValidator(Mockito.any(), Mockito.any())).thenReturn(null);

    testForAllAlgos(client, a -> {
      SignedJWT jws = new SignedJWT(new JWSHeader(a), JUST_SUB_JWT);
      lenient().when(authentication.getJwt()).thenReturn(jws);

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
      lenient().when(authentication.getJwt()).thenReturn(jws);

      try {
        provider.authenticate(authentication);
      } catch (AuthenticationServiceException e) {
        assertThat(e.getMessage(), containsString("invalid signature"));
      }
    });

    lenient().when(client.getTokenEndpointAuthMethod()).thenReturn(AuthMethod.PRIVATE_KEY);

    JWSAlgorithm.Family.SIGNATURE.forEach(a -> {
      SignedJWT jws = new SignedJWT(new JWSHeader(a), JUST_SUB_JWT);
      lenient().when(authentication.getJwt()).thenReturn(jws);

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
      lenient().when(authentication.getJwt()).thenReturn(jws);

      try {
        provider.authenticate(authentication);
      } catch (AuthenticationServiceException e) {
        assertThat(e.getMessage(), containsString("issuer is null"));
      }

      JWTClaimsSet claimSet =
          new JWTClaimsSet.Builder().issuer("invalid-issuer").subject(JWT_AUTH_NAME).build();

      jws = new SignedJWT(header, claimSet);
      lenient().when(authentication.getJwt()).thenReturn(jws);

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
      lenient().when(authentication.getJwt()).thenReturn(jws);

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
      lenient().when(authentication.getJwt()).thenReturn(jws);

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
      lenient().when(authentication.getJwt()).thenReturn(jws);

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
      lenient().when(authentication.getJwt()).thenReturn(jws);

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
      lenient().when(authentication.getJwt()).thenReturn(jws);

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
      lenient().when(authentication.getJwt()).thenReturn(jws);

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
      lenient().when(authentication.getJwt()).thenReturn(jws);

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
      lenient().when(authentication.getJwt()).thenReturn(jws);


      JWTBearerAssertionAuthenticationToken authToken =
          (JWTBearerAssertionAuthenticationToken) provider.authenticate(authentication);
      assertThat(authToken.isAuthenticated(), is(true));
      assertThat(authToken.getName(), is(JWT_AUTH_NAME));
      assertThat(authToken.getAuthorities(), hasItem(ROLE_CLIENT_AUTHORITY));
      assertThat(authToken.getAuthorities(), hasSize(1));
    });
  }

}
