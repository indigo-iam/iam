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
package it.infn.mw.iam.test.logout;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.authn.oidc.validator.OidcIdTokenHintValidator;
import it.infn.mw.iam.core.jwk.JWTSigningAndValidationService;

@ExtendWith(MockitoExtension.class)
class OidcIdTokenHintValidatorTests {

  private static final String ISSUER = "https://iam.example.org";
  private static final String CLIENT_ID = "client";

  @Mock
  private JWTSigningAndValidationService jwtService;

  private OidcIdTokenHintValidator validator;

  @BeforeEach
  void setup() {
    validator = new OidcIdTokenHintValidator(jwtService, ISSUER);
  }

  private SignedJWT createJwt(String issuer, String clientId) throws JOSEException {
    JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder();

    if (issuer != null) {
      claims.issuer(issuer);
    }

    if (clientId != null) {
      claims.audience(clientId);
    }

    SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims.build());

    jwt.sign(new MACSigner("01234567890123456789012345678901"));

    return jwt;
  }

  @Test
  void validTokenReturnsTrue() throws Exception {
    SignedJWT jwt = createJwt(ISSUER, CLIENT_ID);

    when(jwtService.validateSignature(jwt)).thenReturn(true);

    assertTrue(validator.isValid(jwt));
  }

  @Test
  void invalidSignatureReturnsFalse() throws Exception {
    SignedJWT jwt = createJwt(ISSUER, CLIENT_ID);

    when(jwtService.validateSignature(jwt)).thenReturn(false);

    assertFalse(validator.isValid(jwt));
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {"https://other.example.org"})
  void missingOrWrongIssuerReturnFalse(String issuer) throws JOSEException {
    SignedJWT jwt = createJwt(issuer, CLIENT_ID);

    when(jwtService.validateSignature(jwt)).thenReturn(true);

    assertFalse(validator.isValid(jwt));
  }

  @ParameterizedTest
  @NullAndEmptySource
  void missingOrEmptyAudienceReturnFalse(List<String> aud) throws JOSEException {
    JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(ISSUER).audience(aud).build();

    SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);

    when(jwtService.validateSignature(jwt)).thenReturn(true);

    assertFalse(validator.isValid(jwt));
  }
}
