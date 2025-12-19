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
package it.infn.mw.iam.test.oauth.jwk;

import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.aMapWithSize;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;

import java.io.IOException;
import java.text.ParseException;
import java.util.Collections;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mitre.jose.keystore.JWKSetKeyStore;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject.State;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.config.IamProperties.JWKProperties;
import it.infn.mw.iam.core.jwk.IamJWTSigningService;

@ExtendWith(MockitoExtension.class)
class JWTSigningServiceTests implements JWKTestSupport {

  @Mock
  JWKProperties properties;

  @Mock
  JWKSetKeyStore mockKeystore;

  IamJWTSigningService service;

  @Test
  void nullKeystoreIsNotAccepted() {

    NullPointerException e =
        assertThrows(NullPointerException.class, () -> service = new IamJWTSigningService(null));
    assertThat(e.getMessage(), is("null keystore"));
  }

  @Test
  void emptyKeystoreIsNotAccepted() {

    lenient().when(mockKeystore.getKeys()).thenReturn(Collections.emptyList());
    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> service = new IamJWTSigningService(mockKeystore));
    assertThat(e.getMessage(), is("Please provide a non-empty keystore"));
  }

  @Test
  void emptyKeystoreIsNotAcceptedWhenProvidingProperties() {

    lenient().when(mockKeystore.getKeys()).thenReturn(Collections.emptyList());
    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> service = new IamJWTSigningService(properties, mockKeystore));
    assertThat(e.getMessage(), is("empty keystore"));
  }

  @Test
  void rsaSignatureAndVerificationWorks() throws ParseException, IOException {

    service = new IamJWTSigningService(loadKeystore(KS1_LOCATION));

    assertThat(service.getDefaultSignerKeyId(), is("iam1"));
    assertThat(service.getDefaultSigningAlgorithm(), nullValue());
    assertThat(service.getAllPublicKeys(), aMapWithSize(2));
    assertThat(service.getAllPublicKeys().keySet(), hasItems("iam1", "iam2"));

    JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("iam1").build();
    JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject("sub").build();

    SignedJWT signedJwt1 = new SignedJWT(header, claimsSet);
    service.signJwt(signedJwt1);

    assertThat(signedJwt1.getState(), is(State.SIGNED));

    assertThat(service.validateSignature(signedJwt1), is(true));

    assertThat(signedJwt1.getState(), is(State.VERIFIED));

    JWSHeader header2 = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("iam2").build();
    SignedJWT signedJwt2 = new SignedJWT(header2, claimsSet);
    service.signJwt(signedJwt2);

    assertThat(signedJwt2.getState(), is(State.SIGNED));

    assertThat(service.validateSignature(signedJwt2), is(true));
  }

  @Test
  void signerReportsUnknownKey() throws ParseException, IOException {

    JWKSetKeyStore ks = loadKeystore(KS1_LOCATION);
    service = new IamJWTSigningService(ks);

    JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("unknown").build();
    JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject("sub").build();
    SignedJWT signedJwt = new SignedJWT(header, claimsSet);

    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> service.signJwt(signedJwt));
    assertThat(e.getMessage(), is("Signer not found for key unknown"));
  }

  @Test
  void verifyFailsForUnknownKey() throws ParseException, IOException {

    JWKSetKeyStore ks = loadKeystore(KS1_LOCATION);
    service = new IamJWTSigningService(ks);

    JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("unknown").build();
    JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject("sub").build();
    SignedJWT signedJwt = new SignedJWT(header, claimsSet);

    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> service.signJwt(signedJwt));
    assertThat(e.getMessage(), is("Signer not found for key unknown"));
  }

  @Test
  void verifyFailsForInvalidKey() throws ParseException, IOException {

    IamJWTSigningService signer1 = new IamJWTSigningService(loadKeystore(KS1_LOCATION));
    IamJWTSigningService signer2 = new IamJWTSigningService(loadKeystore(KS2_LOCATION));

    JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("iam1").build();
    JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject("sub").build();
    SignedJWT signedJwt = new SignedJWT(header, claimsSet);

    signer1.signJwt(signedJwt);
    assertThat(signer2.validateSignature(signedJwt), is(false));

  }

  @Test
  void exceptionDuringVerifyIsHandled() throws ParseException, IOException, JOSEException {

    IamJWTSigningService signer = new IamJWTSigningService(loadKeystore(KS1_LOCATION));

    JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("iam1").build();

    SignedJWT mockSignedJwt = Mockito.mock(SignedJWT.class);

    Mockito.when(mockSignedJwt.getHeader()).thenReturn(header);
    Mockito.when(mockSignedJwt.verify(ArgumentMatchers.any()))
      .thenThrow(new JOSEException("jose!"));


    assertThat(signer.validateSignature(mockSignedJwt), is(false));

  }

  @Test
  void exceptionDuringSignIsHandled() throws ParseException, IOException, JOSEException {
    IamJWTSigningService signer = new IamJWTSigningService(loadKeystore(KS1_LOCATION));

    JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("iam1").build();

    SignedJWT mockSignedJwt = Mockito.mock(SignedJWT.class);
    Mockito.when(mockSignedJwt.getHeader()).thenReturn(header);

    doThrow(new JOSEException("jose!")).when(mockSignedJwt).sign(ArgumentMatchers.any());
    signer.signJwt(mockSignedJwt);
    assertThat(signer.validateSignature(mockSignedJwt), is(false));
  }

  @Test
  void propertiesParsedCorrectly() throws IOException, ParseException {
    lenient().when(properties.getDefaultJwsAlgorithm()).thenReturn(JWSAlgorithm.RS384.getName());
    lenient().when(properties.getDefaultKeyId()).thenReturn("iam2");

    JWKSetKeyStore ks = new JWKSetKeyStore(loadJWKSet(KS1_LOCATION));
    service = new IamJWTSigningService(properties, ks);

    assertThat(service.getDefaultSignerKeyId(), is("iam2"));
    assertThat(service.getDefaultSigningAlgorithm(), is(JWSAlgorithm.RS384));

  }

  @Test
  void signWithAlgoWorksAsExpected() throws IOException, ParseException {

    JWKSetKeyStore ks = new JWKSetKeyStore(loadJWKSet(KS1_LOCATION));
    service = new IamJWTSigningService(ks);
    JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("iam1").build();
    JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject("sub").build();
    SignedJWT signedJwt = new SignedJWT(header, claimsSet);

    service.signJwt(signedJwt, JWSAlgorithm.ES256);
    assertThat(signedJwt.getState(), is(State.UNSIGNED));

    service.signJwt(signedJwt, JWSAlgorithm.RS384);
    assertThat(signedJwt.getState(), is(State.SIGNED));
  }

  @Test
  void getAllAlgosWorkAsExpected() throws IOException, ParseException {

    JWKSetKeyStore ks = new JWKSetKeyStore(loadJWKSet(KS1_LOCATION));
    service = new IamJWTSigningService(ks);

    assertThat(service.getAllSigningAlgsSupported().containsAll(JWSAlgorithm.Family.RSA), is(true));

  }

}
