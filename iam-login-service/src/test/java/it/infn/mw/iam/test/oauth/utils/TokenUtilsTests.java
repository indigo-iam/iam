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
package it.infn.mw.iam.test.oauth.utils;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Duration;
import java.util.Date;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;

import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.api.aup.AupService;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.ParsedAccessToken;
import it.infn.mw.iam.core.TokenUtils;
import it.infn.mw.iam.core.oauth.scope.pdp.ScopeFilter;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAup;
import it.infn.mw.iam.persistence.model.IamAupSignature;
import it.infn.mw.iam.persistence.model.IamUserInfo;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;

@SuppressWarnings("deprecation")
@ExtendWith(MockitoExtension.class)
class TokenUtilsTests {

  static final String ISSUER = "https://iam.example/";
  static final Payload PAYLOAD = new Payload("test");
  static final String CLIENT_ID = UUID.randomUUID().toString();
  static final String ACCOUNT_ID = UUID.randomUUID().toString();
  static final Set<String> SCOPES = Set.of("read", "write");
  static final Set<String> AUDIENCES = Set.of(CLIENT_ID);

  @Mock
  Clock clock;
  @Mock
  IamProperties iamProperties;
  @Mock
  IamOAuthAccessTokenRepository accessTokenRepo;
  @Mock
  IamAccountRepository accountRepository;
  @Mock
  IamClientRepository clientRepository;
  @Mock
  JWTSigningAndValidationService jwtSigningService;
  @Mock
  ScopeFilter scopeFilter;
  @Mock
  AupService aupService;

  @InjectMocks
  TokenUtils tokenUtils;

  @BeforeEach
  void initClock() {
    lenient().when(clock.instant()).thenReturn(Clock.systemUTC().instant());
    IamAup aup = new IamAup();
    aup.setCreationTime(Date.from(clock.instant()));
    aup.setSignatureValidityInDays(7L);
    lenient().when(iamProperties.getIssuer()).thenReturn(ISSUER);
    lenient().when(aupService.findAup()).thenReturn(Optional.of(aup));
  }

  private SignedJWT mockJwt() {
    SignedJWT jwt = mock(SignedJWT.class);
    lenient().when(jwt.getPayload()).thenReturn(PAYLOAD);
    return jwt;
  }

  private ClientDetailsEntity mockClient(String clientId, boolean isActive) {
    ClientDetailsEntity client = mock(ClientDetailsEntity.class);
    when(client.isActive()).thenReturn(isActive);
    when(clientRepository.findByClientId(clientId)).thenReturn(Optional.of(client));
    return client;
  }

  private IamAupSignature mockAupSignature(Date signatureTime) {

    IamAupSignature aupSignature = mock(IamAupSignature.class);
    lenient().when(aupSignature.getSignatureTime()).thenReturn(signatureTime);
    return aupSignature;
  }

  private IamUserInfo mockUserInfo(boolean isEmailVerified) {

    IamUserInfo userInfo = mock(IamUserInfo.class);
    lenient().when(userInfo.getEmailVerified()).thenReturn(Boolean.valueOf(isEmailVerified));
    return userInfo;
  }

  private IamAccount mockAccount(String accountId, boolean isActive, IamAupSignature aupSignature, IamUserInfo userInfo) {

    IamAccount account = mock(IamAccount.class);
    when(account.getUuid()).thenReturn(accountId);
    when(account.isActive()).thenReturn(isActive);
    lenient().when(account.getAupSignature()).thenReturn(aupSignature);
    lenient().when(account.getUserInfo()).thenReturn(userInfo);
    when(accountRepository.findByUuid(accountId)).thenReturn(Optional.of(account));
    return account;
  }

  private void mockValidateSignature(SignedJWT jwt, boolean validationResult) {
    lenient().when(jwtSigningService.validateSignature(jwt)).thenReturn(validationResult);
  }

  private ParsedAccessToken clientToken(String issuer, String clientId, Date expiration,
      SignedJWT jwt) {
    return userToken(issuer, clientId, clientId, expiration, jwt);
  }

  private ParsedAccessToken userToken(String issuer, String accountId, String clientId,
      Date expiration, SignedJWT jwt) {
    return buildToken(issuer, accountId, clientId, expiration, SCOPES, AUDIENCES, jwt);
  }

  private ParsedAccessToken buildToken(String issuer, String sub, String clientId, Date expiration,
      Set<String> scopes, Set<String> audiences, SignedJWT jwt) {
    return new ParsedAccessToken(issuer, sub, clientId, expiration, scopes, audiences,
        jwt.getHeader(), jwt.getPayload(), jwt.getSignature(), jwt, null, null);
  }

  @Test
  void parseAccessTokenWithInvalidTokenThrowsException() {

    String invalid = "not-a-jwt";
    assertThrows(InvalidTokenException.class, () -> tokenUtils.parseAccessToken(invalid));
  }

  @Test
  void validateValidTokenDoesNotThrowExceptions() {

    mockClient(CLIENT_ID, true);

    SignedJWT jwt = mockJwt();
    ParsedAccessToken token =
        clientToken(ISSUER, CLIENT_ID, Date.from(clock.instant().plusSeconds(3600)), jwt);
    mockValidateSignature(jwt, true);

    assertDoesNotThrow(() -> tokenUtils.validate(token));
  }

  @Test
  void validateExpiredTokenThrowsException() {

    SignedJWT jwt = mockJwt();
    ParsedAccessToken token =
        clientToken(ISSUER, CLIENT_ID, Date.from(clock.instant().minusSeconds(3600)), jwt);
    mockValidateSignature(jwt, true);

    assertThrows(InvalidTokenException.class, () -> tokenUtils.validate(token));
  }

  @Test
  void validateTokenWithNullExpThrowsException() {

    SignedJWT jwt = mockJwt();
    ParsedAccessToken token =
        clientToken(ISSUER, CLIENT_ID, null, jwt);
    mockValidateSignature(jwt, true);

    assertThrows(InvalidTokenException.class, () -> tokenUtils.validate(token));
  }

  @Test
  void validateTokenWithNullIssuerThrowsException() {

    SignedJWT jwt = mockJwt();
    ParsedAccessToken token =
        clientToken(null, CLIENT_ID, Date.from(clock.instant().plusSeconds(3600)), jwt);
    mockValidateSignature(jwt, true);

    assertThrows(InvalidTokenException.class, () -> tokenUtils.validate(token));
  }

  @Test
  void validateTokenWithWrongIssuerThrowsException() {

    SignedJWT jwt = mockJwt();
    ParsedAccessToken token =
        clientToken("fake-issuer", CLIENT_ID, Date.from(clock.instant().plusSeconds(3600)), jwt);
    mockValidateSignature(jwt, true);

    assertThrows(InvalidTokenException.class, () -> tokenUtils.validate(token));
  }

  @Test
  void validateInvalidSignatureThrowsException() {

    SignedJWT jwt = mock(SignedJWT.class);
    Payload payload = new Payload("test");;

    when(jwt.getPayload()).thenReturn(payload);
    when(jwtSigningService.validateSignature(jwt)).thenReturn(false);

    Date validExp = Date.from(clock.instant().plusSeconds(3600));
    ParsedAccessToken token =
        buildToken(ISSUER, CLIENT_ID, CLIENT_ID, validExp, SCOPES, AUDIENCES, jwt);

    assertThrows(InvalidTokenException.class, () -> tokenUtils.validate(token));
  }

  @Test
  void validateTokenWithInactiveClientThrowsException() {

    mockClient(CLIENT_ID, false);

    SignedJWT jwt = mockJwt();
    ParsedAccessToken token =
        clientToken(ISSUER, CLIENT_ID, Date.from(clock.instant().plusSeconds(3600)), jwt);
    mockValidateSignature(jwt, true);

    assertThrows(InvalidTokenException.class, () -> tokenUtils.validate(token));
  }

  @Test
  void validateTokenWithNotFoundClientThrowsException() {

    when(clientRepository.findByClientId(CLIENT_ID)).thenReturn(Optional.empty());

    SignedJWT jwt = mockJwt();
    ParsedAccessToken token =
        clientToken(ISSUER, CLIENT_ID, Date.from(clock.instant().plusSeconds(3600)), jwt);
    mockValidateSignature(jwt, true);

    assertThrows(NoSuchElementException.class, () -> tokenUtils.validate(token));
  }

  @Test
  void validateUserTokenWithNotFoundAccountThrowsException() {

    mockClient(CLIENT_ID, true);

    SignedJWT jwt = mockJwt();
    ParsedAccessToken token =
        userToken(ISSUER, ACCOUNT_ID, CLIENT_ID, Date.from(clock.instant().plusSeconds(3600)), jwt);
    mockValidateSignature(jwt, true);

    when(accountRepository.findByUuid(ACCOUNT_ID)).thenReturn(Optional.empty());

    InvalidTokenException e =
        assertThrows(InvalidTokenException.class, () -> tokenUtils.validate(token));
    assertEquals("User with uuid " + ACCOUNT_ID + " not found", e.getMessage());
  }

  @Test
  void validateUserTokenWithDisabledAccountThrowsException() {

    mockClient(CLIENT_ID, true);

    SignedJWT jwt = mockJwt();
    ParsedAccessToken token =
        userToken(ISSUER, ACCOUNT_ID, CLIENT_ID, Date.from(clock.instant().plusSeconds(3600)), jwt);
    mockValidateSignature(jwt, true);

    mockAccount(ACCOUNT_ID, false, null, mockUserInfo(true));

    InvalidTokenException e =
        assertThrows(InvalidTokenException.class, () -> tokenUtils.validate(token));
    assertEquals("User with uuid " + ACCOUNT_ID + " is not active", e.getMessage());
  }

  @Test
  void validateUserTokenWithNoAupSignatureThrowsException() {

    mockClient(CLIENT_ID, true);

    SignedJWT jwt = mockJwt();
    ParsedAccessToken token =
        userToken(ISSUER, ACCOUNT_ID, CLIENT_ID, Date.from(clock.instant().plusSeconds(3600)), jwt);
    mockValidateSignature(jwt, true);

    mockAccount(ACCOUNT_ID, true, null, mockUserInfo(true));

    InvalidTokenException e =
        assertThrows(InvalidTokenException.class, () -> tokenUtils.validate(token));
    assertEquals("User with uuid " + ACCOUNT_ID + " needs to sign AUP for this organization in order to proceed.", e.getMessage());
  }

  @Test
  void validateUserTokenWithExpiredAupSignatureThrowsException() {

    mockClient(CLIENT_ID, true);

    SignedJWT jwt = mockJwt();
    ParsedAccessToken token =
        userToken(ISSUER, ACCOUNT_ID, CLIENT_ID, Date.from(clock.instant().plusSeconds(3600)), jwt);
    mockValidateSignature(jwt, true);

    mockAccount(ACCOUNT_ID, true, mockAupSignature(Date.from(clock.instant().minus(Duration.ofDays(10)))), mockUserInfo(true));

    InvalidTokenException e =
        assertThrows(InvalidTokenException.class, () -> tokenUtils.validate(token));
    assertEquals("User with uuid " + ACCOUNT_ID + " needs to sign AUP for this organization in order to proceed.", e.getMessage());
  }

}
