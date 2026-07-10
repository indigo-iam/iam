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

import static it.infn.mw.iam.authn.util.SessionUtils.NONCE_SESSION_VARIABLE;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.text.ParseException;
import java.time.Clock;
import java.util.Date;

import javax.servlet.http.HttpSession;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mockito.Mock;
import org.springframework.security.authentication.AuthenticationServiceException;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.JsonObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.PlainHeader;
import com.nimbusds.jose.shaded.gson.JsonArray;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.authn.util.JwtUtils;
import it.infn.mw.iam.authn.util.SessionUtils;

class JwtUtilsValidationTests {

  @Mock
  private Clock clock;

  @Mock
  private ObjectMapper objectMapper;

  private Date skewedMin;
  private Date skewedMax;

  private static final String ISSUER = "https://test.example";
  private static final String CLIENT_ID = "client";

  @BeforeEach
  void setUp() {
    clock = Clock.systemUTC();
    skewedMin = Date.from(clock.instant().minusSeconds(300));
    skewedMax = Date.from(clock.instant().plusSeconds(300));
  }

  @Test
  void testThrowExceptionWhenParsingJwtClaimsFails() throws Exception {

    JWT jwt = mock(JWT.class);
    when(jwt.getJWTClaimsSet()).thenThrow(new ParseException("invalid claims", 0));

    AuthenticationServiceException ex =
        assertThrows(AuthenticationServiceException.class, () -> JwtUtils.parseClaims(jwt));
    assertEquals("Error parsing JWT claims: invalid claims", ex.getMessage());
  }

  @Test
  void testThrowExceptionWhenParsingJwtTokenFails() {

    AuthenticationServiceException ex =
        assertThrows(AuthenticationServiceException.class, () -> JwtUtils.parseToken("abc.def"));
    assertEquals("Token parse error", ex.getMessage());
  }

  @Test
  void testParseJsonObjectSuccessfully() {

    JsonObject json = new JsonObject();
    json.addProperty("access_token", "abc");

    JsonObject result = JwtUtils.jsonStringSanityChecks(json.toString());
    assertEquals("abc", result.get("access_token").getAsString());
  }

  @Test
  void testThrowExceptionWhenJsonIsNotObject() {

    JsonArray json = new JsonArray();
    json.add("value");
    String invalidJson = json.toString();

    AuthenticationServiceException ex = assertThrows(AuthenticationServiceException.class,
        () -> JwtUtils.jsonStringSanityChecks(invalidJson));
    assertTrue(ex.getMessage().contains("Not a JSON object"));
  }

  @Test
  void testThrowExceptionWhenTokenIssuerIsNull() {

    JWTClaimsSet claims =
        new JWTClaimsSet.Builder().expirationTime(Date.from(clock.instant().plusSeconds(3600)))
          .build();

    AuthenticationServiceException ex = assertThrows(AuthenticationServiceException.class,
        () -> JwtUtils.validateClaims(claims, ISSUER, CLIENT_ID, skewedMin, skewedMax));
    assertEquals("Issuer claim not present in the ID token", ex.getMessage());
  }

  @Test
  void testThrowExceptionWhenTokenIssuerDoesNotMatch() {

    JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer("https://wrong-issuer.example")
      .expirationTime(Date.from(clock.instant().plusSeconds(3600)))
      .build();

    AuthenticationServiceException ex = assertThrows(AuthenticationServiceException.class,
        () -> JwtUtils.validateClaims(claims, ISSUER, CLIENT_ID, skewedMin, skewedMax));
    assertTrue(
        ex.getMessage().contains("ID token issuer claim does not match the client configuration"));
  }

  @Test
  void testThrowExceptionWhenExpirationIsMissing() {

    JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(ISSUER).build();

    AuthenticationServiceException ex = assertThrows(AuthenticationServiceException.class,
        () -> JwtUtils.validateClaims(claims, ISSUER, CLIENT_ID, skewedMin, skewedMax));
    assertEquals("ID token does not have required expiration claim", ex.getMessage());
  }

  @Test
  void testThrowExceptionWhenTokenIsExpired() {

    JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(ISSUER)
      .expirationTime(Date.from(clock.instant().minusSeconds(500)))
      .build();

    AuthenticationServiceException ex = assertThrows(AuthenticationServiceException.class,
        () -> JwtUtils.validateClaims(claims, ISSUER, CLIENT_ID, skewedMin, skewedMax));
    assertTrue(ex.getMessage().contains("ID token is expired"));
  }

  @Test
  void testThrowExceptionWhenNotBeforeIsInFuture() {

    JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(ISSUER)
      .expirationTime(Date.from(clock.instant().plusSeconds(3600)))
      .issueTime(Date.from(clock.instant()))
      .notBeforeTime(Date.from(clock.instant().plusSeconds(500)))
      .audience("client")
      .build();

    AuthenticationServiceException ex = assertThrows(AuthenticationServiceException.class,
        () -> JwtUtils.validateClaims(claims, ISSUER, CLIENT_ID, skewedMin, skewedMax));
    assertTrue(ex.getMessage().contains("ID token not valid until"));
  }

  @Test
  void testThrowExceptionWhenIssuedAtMissing() {

    JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(ISSUER)
      .expirationTime(Date.from(clock.instant().plusSeconds(3600)))
      .build();

    AuthenticationServiceException ex = assertThrows(AuthenticationServiceException.class,
        () -> JwtUtils.validateClaims(claims, ISSUER, CLIENT_ID, skewedMin, skewedMax));
    assertEquals("ID token does not have required issued-at claim", ex.getMessage());
  }

  @Test
  void testThrowExceptionWhenIssuedAtIsInTheFuture() {

    JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(ISSUER)
      .expirationTime(Date.from(clock.instant().plusSeconds(3600)))
      .issueTime(Date.from(clock.instant().plusSeconds(500)))
      .audience("client")
      .build();

    AuthenticationServiceException ex = assertThrows(AuthenticationServiceException.class,
        () -> JwtUtils.validateClaims(claims, ISSUER, CLIENT_ID, skewedMin, skewedMax));
    assertTrue(ex.getMessage().contains("ID token was issued in the future"));
  }

  @Test
  void testThrowExceptionWhenAudienceIsEmpty() {

    JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(ISSUER)
      .expirationTime(Date.from(clock.instant().plusSeconds(3600)))
      .issueTime(Date.from(clock.instant()))
      .build();

    AuthenticationServiceException ex = assertThrows(AuthenticationServiceException.class,
        () -> JwtUtils.validateClaims(claims, ISSUER, CLIENT_ID, skewedMin, skewedMax));

    assertEquals("Audience claim not present in the ID token", ex.getMessage());
  }

  @Test
  void testThrowExceptionWhenAudienceDoesNotContainClientId() {

    JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(ISSUER)
      .expirationTime(Date.from(clock.instant().plusSeconds(3600)))
      .issueTime(Date.from(clock.instant()))
      .audience("other-client")
      .build();

    AuthenticationServiceException ex = assertThrows(AuthenticationServiceException.class,
        () -> JwtUtils.validateClaims(claims, ISSUER, CLIENT_ID, skewedMin, skewedMax));
    assertTrue(ex.getMessage()
      .contains("ID token audience claim does not match the client configuration"));
  }

  @Test
  void testThrowExceptionWhenAlgorithmDoesNotMatch() {

    SignedJWT jwt = mock(SignedJWT.class);
    JWSHeader header = new JWSHeader(JWSAlgorithm.RS256);

    when(jwt.getHeader()).thenReturn(header);

    AuthenticationServiceException ex = assertThrows(AuthenticationServiceException.class,
        () -> JwtUtils.validateSignature(jwt, "RS512", null));
    assertEquals("Token algorithm RS256 does not match expected algorithm RS512", ex.getMessage());
  }

  @Test
  void testThrowExceptionForPlainJwt() {

    PlainJWT jwt = mock(PlainJWT.class);
    PlainHeader header = new PlainHeader();
    when(jwt.getHeader()).thenReturn(header);

    AuthenticationServiceException ex = assertThrows(AuthenticationServiceException.class,
        () -> JwtUtils.validateSignature(jwt, null, null));
    assertEquals("Unsigned ID tokens can only be used if explicitly configured in client.",
        ex.getMessage());
  }

  @Test
  void testThrowExceptionForHs256() {

    SignedJWT jwt = mock(SignedJWT.class);
    when(jwt.getHeader()).thenReturn(new JWSHeader(JWSAlgorithm.HS256));

    UnsupportedOperationException ex = assertThrows(UnsupportedOperationException.class,
        () -> JwtUtils.validateSignature(jwt, "HS256", null));
    assertEquals("Symmetric ID token signing agorithm HS256 is not supported", ex.getMessage());

    when(jwt.getHeader()).thenReturn(new JWSHeader(JWSAlgorithm.HS384));

    ex = assertThrows(UnsupportedOperationException.class,
        () -> JwtUtils.validateSignature(jwt, "HS384", null));
    assertEquals("Symmetric ID token signing agorithm HS384 is not supported", ex.getMessage());

    when(jwt.getHeader()).thenReturn(new JWSHeader(JWSAlgorithm.HS512));

    ex = assertThrows(UnsupportedOperationException.class,
        () -> JwtUtils.validateSignature(jwt, "HS512", null));
    assertEquals("Symmetric ID token signing agorithm HS512 is not supported", ex.getMessage());
  }

  @Test
  void testThrowExceptionWhenValidatorIsNull() {

    SignedJWT jwt = mock(SignedJWT.class);
    when(jwt.getHeader()).thenReturn(new JWSHeader(JWSAlgorithm.RS256));

    AuthenticationServiceException ex = assertThrows(AuthenticationServiceException.class,
        () -> JwtUtils.validateSignature(jwt, "RS256", null));
    assertEquals("Unable to find an appropriate signature validator for ID token", ex.getMessage());
  }

  @Test
  void testThrowExceptionWhenSignatureValidationFails() {

    SignedJWT jwt = mock(SignedJWT.class);
    when(jwt.getHeader()).thenReturn(new JWSHeader(JWSAlgorithm.RS256));

    JWTSigningAndValidationService validator = mock(JWTSigningAndValidationService.class);
    when(validator.validateSignature(jwt)).thenReturn(false);

    AuthenticationServiceException ex = assertThrows(AuthenticationServiceException.class,
        () -> JwtUtils.validateSignature(jwt, "RS256", validator));
    assertEquals("ID token signature validation failed", ex.getMessage());
  }

  @Test
  void testValidateSignatureSuccess() {

    SignedJWT jwt = mock(SignedJWT.class);
    when(jwt.getHeader()).thenReturn(new JWSHeader(JWSAlgorithm.RS256));

    JWTSigningAndValidationService validator = mock(JWTSigningAndValidationService.class);
    when(validator.validateSignature(jwt)).thenReturn(true);

    assertDoesNotThrow(() -> JwtUtils.validateSignature(jwt, "RS256", validator));
  }

  @Test
  void testThrowExceptionWhenNonceClaimParsingFails() {

    JWTClaimsSet claims = new JWTClaimsSet.Builder().claim("nonce", 12345).build();
    HttpSession session = mock(HttpSession.class);

    AuthenticationServiceException ex = assertThrows(AuthenticationServiceException.class,
        () -> SessionUtils.validateNonceSession(session, claims));
    assertTrue(ex.getMessage().contains("nonce claim parse error"));
  }

  @Test
  void testThrowExceptionWhenNonceIsMissing() {

    JWTClaimsSet claims = new JWTClaimsSet.Builder().build();
    HttpSession session = mock(HttpSession.class);

    AuthenticationServiceException ex = assertThrows(AuthenticationServiceException.class,
        () -> SessionUtils.validateNonceSession(session, claims));
    assertEquals("ID token did not contain a nonce claim.", ex.getMessage());

    JWTClaimsSet claimsEmptyNonce = new JWTClaimsSet.Builder().claim("nonce", "").build();

    ex = assertThrows(AuthenticationServiceException.class,
        () -> SessionUtils.validateNonceSession(session, claimsEmptyNonce));
    assertEquals("ID token did not contain a nonce claim.", ex.getMessage());
  }

  @Test
  void testThrowExceptionWhenNonceDoesNotMatchSession() {

    JWTClaimsSet claims = new JWTClaimsSet.Builder().claim("nonce", "token-nonce").build();
    HttpSession session = mock(HttpSession.class);

    when(session.getAttribute(NONCE_SESSION_VARIABLE)).thenReturn("session-nonce");

    AuthenticationServiceException ex = assertThrows(AuthenticationServiceException.class,
        () -> SessionUtils.validateNonceSession(session, claims));
    assertTrue(ex.getMessage().contains("Possible replay attack detected"));
    assertTrue(ex.getMessage().contains("Expected session-nonce got token-nonce"));
  }

  @Test
  void testValidateNonceSuccessfully() {

    JWTClaimsSet claims = new JWTClaimsSet.Builder().claim("nonce", "same-nonce").build();

    HttpSession session = mock(HttpSession.class);
    when(session.getAttribute(NONCE_SESSION_VARIABLE)).thenReturn("same-nonce");

    assertDoesNotThrow(() -> SessionUtils.validateNonceSession(session, claims));
  }

}
