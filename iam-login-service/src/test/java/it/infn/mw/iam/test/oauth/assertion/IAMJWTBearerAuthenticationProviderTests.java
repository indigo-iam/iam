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
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Date;
import java.util.UUID;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mitre.jwt.signer.service.impl.ClientKeyCacheService;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.ClientDetailsEntity.AuthMethod;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.openid.connect.assertion.JWTBearerAssertionAuthenticationToken;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
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

@RunWith(MockitoJUnitRunner.class)
public class IAMJWTBearerAuthenticationProviderTests
    implements IAMJWTBearerAuthenticationProviderTestSupport {

  public static final Instant NOW = Instant.parse("2021-01-01T00:00:00.00Z");

  private Clock clock = Clock.fixed(NOW, ZoneId.systemDefault());

  @Mock
  private ClientDetailsEntityService clientService;

  @Mock
  private ClientKeyCacheService validators;

  @Mock
  private IamProperties iamProperties;

  @Mock
  private JWTBearerAssertionAuthenticationToken authentication;

  @Mock
  private JWTSigningAndValidationService validator;

  @Mock
  private ClientDetailsEntity client;

  IAMJWTBearerAuthenticationProvider provider;


  @Before
  public void setup() {
    when(authentication.getName()).thenReturn(JWT_AUTH_NAME);
    when(iamProperties.getIssuer()).thenReturn(ISSUER);
    when(clientService.loadClientByClientId(JWT_AUTH_NAME)).thenReturn(client);
    when(client.getClientId()).thenReturn(JWT_AUTH_NAME);
    when(validators.getValidator(Mockito.any(), Mockito.any())).thenReturn(validator);
    when(validator.validateSignature(Mockito.any())).thenReturn(true);

    provider =
        new IAMJWTBearerAuthenticationProvider(clock, iamProperties, clientService, validators);
  }

  @Test(expected = UsernameNotFoundException.class)
  public void testClientNotFoundTriggersUsernameNotFoundException() {

    when(clientService.loadClientByClientId(JWT_AUTH_NAME)).thenReturn(null);

    try {
      provider.authenticate(authentication);
    } catch (UsernameNotFoundException e) {
      assertThat(e.getMessage(), containsString("Unknown client"));
      throw e;
    }
  }

  @Test(expected = AuthenticationServiceException.class)
  public void testPlainJwtTriggersException() {

    when(authentication.getJwt())
      .thenReturn(new PlainJWT(new JWTClaimsSet.Builder().subject("sub").build()));

    try {
      provider.authenticate(authentication);
    } catch (AuthenticationServiceException e) {
      assertThat(e.getMessage(), containsString("Unsupported JWT type"));
      throw e;
    }
  }

  @Test(expected = AuthenticationServiceException.class)
  public void testNullJwtTriggersException() {

    try {
      provider.authenticate(authentication);
    } catch (AuthenticationServiceException e) {
      assertThat(e.getMessage(), containsString("Null JWT"));
      throw e;
    }
  }

  @Test
  public void testUnsupportClientAuthMethodTriggersException() throws JOSEException {

    when(authentication.getJwt()).thenReturn(macSignJwt(JUST_SUB_JWT));

    when(client.getTokenEndpointAuthMethod()).thenReturn(null, AuthMethod.NONE,
        AuthMethod.SECRET_BASIC, AuthMethod.SECRET_POST);

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
  public void testInvalidAsymmetricAlgo() throws JOSEException {

    when(client.getTokenEndpointAuthMethod()).thenReturn(AuthMethod.SECRET_JWT);

    JWSAlgorithm.Family.SIGNATURE.forEach(a -> {
      SignedJWT jws = new SignedJWT(new JWSHeader(a), JUST_SUB_JWT);
      when(authentication.getJwt()).thenReturn(jws);

      try {
        provider.authenticate(authentication);
      } catch (AuthenticationServiceException e) {
        assertThat(e.getMessage(), containsString("Invalid signature algorithm: " + a.getName()));
      }
    });
  }

  @Test
  public void testInvalidSymmetricAlgo() throws JOSEException {

    when(client.getTokenEndpointAuthMethod()).thenReturn(AuthMethod.PRIVATE_KEY);

    JWSAlgorithm.Family.HMAC_SHA.forEach(a -> {
      SignedJWT jws = new SignedJWT(new JWSHeader(a), JUST_SUB_JWT);
      when(authentication.getJwt()).thenReturn(jws);

      try {
        provider.authenticate(authentication);
      } catch (AuthenticationServiceException e) {
        assertThat(e.getMessage(), containsString("Invalid signature algorithm: " + a.getName()));
      }
    });

  }

  @Test
  public void testValidatorNotFound() throws JOSEException {

    when(validators.getValidator(Mockito.any(), Mockito.any())).thenReturn(null);

    testForAllAlgos(client, a -> {
      SignedJWT jws = new SignedJWT(new JWSHeader(a), JUST_SUB_JWT);
      when(authentication.getJwt()).thenReturn(jws);

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
  public void testInvalidSignatureHandled() throws JOSEException {

    when(validators.getValidator(Mockito.any(), Mockito.any())).thenReturn(validator);
    when(validator.validateSignature(Mockito.any())).thenReturn(false);

    when(client.getTokenEndpointAuthMethod()).thenReturn(AuthMethod.SECRET_JWT);

    JWSAlgorithm.Family.HMAC_SHA.forEach(a -> {
      SignedJWT jws = new SignedJWT(new JWSHeader(a), JUST_SUB_JWT);
      when(authentication.getJwt()).thenReturn(jws);

      try {
        provider.authenticate(authentication);
      } catch (AuthenticationServiceException e) {
        assertThat(e.getMessage(), containsString("invalid signature"));
      }
    });

    when(client.getTokenEndpointAuthMethod()).thenReturn(AuthMethod.PRIVATE_KEY);

    JWSAlgorithm.Family.SIGNATURE.forEach(a -> {
      SignedJWT jws = new SignedJWT(new JWSHeader(a), JUST_SUB_JWT);
      when(authentication.getJwt()).thenReturn(jws);

      try {
        provider.authenticate(authentication);
      } catch (AuthenticationServiceException e) {
        assertThat(e.getMessage(), containsString("invalid signature"));
      }
    });
  }

  @Test
  public void testInvalidAssertionIssuer() {

    when(validators.getValidator(Mockito.any(), Mockito.any())).thenReturn(validator);
    when(validator.validateSignature(Mockito.any())).thenReturn(true);

    testForAllAlgos(client, a -> {

      JWSHeader header = new JWSHeader(a);
      SignedJWT jws = new SignedJWT(header, JUST_SUB_JWT);
      when(authentication.getJwt()).thenReturn(jws);

      try {
        provider.authenticate(authentication);
      } catch (AuthenticationServiceException e) {
        assertThat(e.getMessage(), containsString("issuer is null"));
      }

      JWTClaimsSet claimSet =
          new JWTClaimsSet.Builder().issuer("invalid-issuer").subject(JWT_AUTH_NAME).build();

      jws = new SignedJWT(header, claimSet);
      when(authentication.getJwt()).thenReturn(jws);

      try {
        provider.authenticate(authentication);
      } catch (AuthenticationServiceException e) {
        assertThat(e.getMessage(), containsString("issuer does not match client id"));
      }
    });

  }

  @Test
  public void testExpirationTimeNotSet() {

    when(validators.getValidator(Mockito.any(), Mockito.any())).thenReturn(validator);
    when(validator.validateSignature(Mockito.any())).thenReturn(true);

    testForAllAlgos(client, a -> {
      JWSHeader header = new JWSHeader(a);
      JWTClaimsSet claimSet =
          new JWTClaimsSet.Builder().issuer(JWT_AUTH_NAME).subject(JWT_AUTH_NAME).build();
      SignedJWT jws = new SignedJWT(header, claimSet);
      when(authentication.getJwt()).thenReturn(jws);

      try {
        provider.authenticate(authentication);
      } catch (AuthenticationServiceException e) {
        assertThat(e.getMessage(), containsString("expiration time not set"));
      }

    });
  }

  @Test
  public void testExpirationInThePast() {

    when(validators.getValidator(Mockito.any(), Mockito.any())).thenReturn(validator);
    when(validator.validateSignature(Mockito.any())).thenReturn(true);

    testForAllAlgos(client, a -> {
      JWSHeader header = new JWSHeader(a);
      JWTClaimsSet claimSet = new JWTClaimsSet.Builder().issuer(JWT_AUTH_NAME)
        .subject(JWT_AUTH_NAME)
        .expirationTime(Date.from(clock.instant().minusSeconds(301)))
        .build();
      SignedJWT jws = new SignedJWT(header, claimSet);
      when(authentication.getJwt()).thenReturn(jws);

      try {
        provider.authenticate(authentication);
      } catch (AuthenticationServiceException e) {
        assertThat(e.getMessage(), containsString("expired assertion token"));
      }

    });
  }

  @Test
  public void testNotBeforeInTheFuture() {

    when(validators.getValidator(Mockito.any(), Mockito.any())).thenReturn(validator);
    when(validator.validateSignature(Mockito.any())).thenReturn(true);

    testForAllAlgos(client, a -> {
      JWSHeader header = new JWSHeader(a);
      JWTClaimsSet claimSet = new JWTClaimsSet.Builder().issuer(JWT_AUTH_NAME)
        .subject(JWT_AUTH_NAME)
        .expirationTime(Date.from(clock.instant().plusSeconds(1800)))
        .notBeforeTime(Date.from(clock.instant().plusSeconds(900)))
        .build();
      SignedJWT jws = new SignedJWT(header, claimSet);
      when(authentication.getJwt()).thenReturn(jws);

      try {
        provider.authenticate(authentication);
      } catch (AuthenticationServiceException e) {
        assertThat(e.getMessage(), containsString("assertion is not yet valid"));
      }

    });
  }

  @Test
  public void testIssuedInTheFuture() {

    when(validators.getValidator(Mockito.any(), Mockito.any())).thenReturn(validator);
    when(validator.validateSignature(Mockito.any())).thenReturn(true);

    testForAllAlgos(client, a -> {
      JWSHeader header = new JWSHeader(a);
      JWTClaimsSet claimSet = new JWTClaimsSet.Builder().issuer(JWT_AUTH_NAME)
        .subject(JWT_AUTH_NAME)
        .expirationTime(Date.from(clock.instant().plusSeconds(1800)))
        .issueTime(Date.from(clock.instant().plusSeconds(1000)))
        .build();
      SignedJWT jws = new SignedJWT(header, claimSet);
      when(authentication.getJwt()).thenReturn(jws);

      try {
        provider.authenticate(authentication);
      } catch (AuthenticationServiceException e) {
        assertThat(e.getMessage(), containsString("assertion was issued in the future"));
      }

    });
  }

  @Test
  public void testNullAudience() {

    when(validators.getValidator(Mockito.any(), Mockito.any())).thenReturn(validator);
    when(validator.validateSignature(Mockito.any())).thenReturn(true);

    testForAllAlgos(client, a -> {
      JWSHeader header = new JWSHeader(a);
      JWTClaimsSet claimSet = new JWTClaimsSet.Builder().issuer(JWT_AUTH_NAME)
        .subject(JWT_AUTH_NAME)
        .expirationTime(Date.from(clock.instant().plusSeconds(1800)))
        .build();
      SignedJWT jws = new SignedJWT(header, claimSet);
      when(authentication.getJwt()).thenReturn(jws);

      try {
        provider.authenticate(authentication);
      } catch (AuthenticationServiceException e) {
        assertThat(e.getMessage(), containsString("invalid audience"));
      }

    });
  }

  @Test
  public void testInvalidAudience() {

    when(validators.getValidator(Mockito.any(), Mockito.any())).thenReturn(validator);
    when(validator.validateSignature(Mockito.any())).thenReturn(true);

    testForAllAlgos(client, a -> {
      JWSHeader header = new JWSHeader(a);
      JWTClaimsSet claimSet = new JWTClaimsSet.Builder().issuer(JWT_AUTH_NAME)
        .subject(JWT_AUTH_NAME)
        .expirationTime(Date.from(clock.instant().plusSeconds(1800)))
        .audience(singletonList("invalid-audience"))
        .build();
      SignedJWT jws = new SignedJWT(header, claimSet);
      when(authentication.getJwt()).thenReturn(jws);

      try {
        provider.authenticate(authentication);
      } catch (AuthenticationServiceException e) {
        assertThat(e.getMessage(), containsString("invalid audience"));
      }

    });
  }

  @Test
  public void testJTIRequired() {

    when(validators.getValidator(Mockito.any(), Mockito.any())).thenReturn(validator);
    when(validator.validateSignature(Mockito.any())).thenReturn(true);

    testForAllAlgos(client, a -> {
      JWSHeader header = new JWSHeader(a);
      JWTClaimsSet claimSet = new JWTClaimsSet.Builder().issuer(JWT_AUTH_NAME)
        .subject(JWT_AUTH_NAME)
        .expirationTime(Date.from(clock.instant().plusSeconds(1800)))
        .audience(singletonList(ISSUER_TOKEN_ENDPOINT))
        .build();
      SignedJWT jws = new SignedJWT(header, claimSet);
      when(authentication.getJwt()).thenReturn(jws);

      try {
        provider.authenticate(authentication);
      } catch (AuthenticationServiceException e) {
        assertThat(e.getMessage(), containsString("jti is null"));
      }

    });
  }

  @Test
  public void testValidAssertion() {

    when(validators.getValidator(Mockito.any(), Mockito.any())).thenReturn(validator);
    when(validator.validateSignature(Mockito.any())).thenReturn(true);

    testForAllAlgos(client, a -> {
      JWSHeader header = new JWSHeader(a);
      JWTClaimsSet claimSet = new JWTClaimsSet.Builder().issuer(JWT_AUTH_NAME)
        .subject(JWT_AUTH_NAME)
        .expirationTime(Date.from(clock.instant().plusSeconds(1800)))
        .audience(singletonList(ISSUER_TOKEN_ENDPOINT))
        .jwtID(UUID.randomUUID().toString())
        .build();
      SignedJWT jws = new SignedJWT(header, claimSet);
      when(authentication.getJwt()).thenReturn(jws);


      JWTBearerAssertionAuthenticationToken authToken =
          (JWTBearerAssertionAuthenticationToken) provider.authenticate(authentication);
      assertThat(authToken.isAuthenticated(), is(true));
      assertThat(authToken.getName(), is(JWT_AUTH_NAME));
      assertThat(authToken.getAuthorities(), hasItem(ROLE_CLIENT_AUTHORITY));
      assertThat(authToken.getAuthorities(), hasSize(1));


    });
  }

}
