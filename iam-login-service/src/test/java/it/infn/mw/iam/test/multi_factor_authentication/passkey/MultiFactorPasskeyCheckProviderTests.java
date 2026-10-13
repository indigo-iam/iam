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
package it.infn.mw.iam.test.multi_factor_authentication.passkey;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.CannotAcquireLockException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.IamPasskeyService;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyAssertionDTO;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyChallenge;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyChallenge.Purpose;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.error.PasskeyCeremonyException;
import it.infn.mw.iam.authn.multi_factor_authentication.IamAuthenticationMethodReference;
import it.infn.mw.iam.authn.multi_factor_authentication.MultiFactorPasskeyCheckProvider;
import it.infn.mw.iam.authn.multi_factor_authentication.PasskeyAssertionAuthenticationToken;
import it.infn.mw.iam.authn.util.Authorities;
import it.infn.mw.iam.core.ExtendedAuthenticationToken;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamPasskey;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.multi_factor_authentication.passkey.PasskeyTestAuthenticator.Algorithm;

@ExtendWith(MockitoExtension.class)
class MultiFactorPasskeyCheckProviderTests extends PasskeyTestSupport {

  private static final String USERNAME = "test-user";

  @Mock
  IamAccountRepository accountRepo;

  @Mock
  IamPasskeyService passkeyService;

  MultiFactorPasskeyCheckProvider provider;
  IamAccount account;
  PasskeyChallenge challenge;
  ObjectMapper mapper = new ObjectMapper();

  @BeforeEach
  void setup() {
    provider = new MultiFactorPasskeyCheckProvider(accountRepo, passkeyService);
    account = IamAccount.newAccount();
    account.setUsername(USERNAME);
    challenge = new PasskeyChallenge(new byte[32], Purpose.AUTHENTICATION, USERNAME,
        java.time.Instant.now().plusSeconds(60));
  }

  private ExtendedAuthenticationToken preAuthenticatedToken() {
    ExtendedAuthenticationToken token = new ExtendedAuthenticationToken(USERNAME, "secret",
        List.of(Authorities.ROLE_PRE_AUTHENTICATED));
    token.setAuthenticated(false);
    token.setPreAuthenticated(true);
    Set<IamAuthenticationMethodReference> refs = new HashSet<>();
    refs.add(new IamAuthenticationMethodReference("pwd"));
    token.setAuthenticationMethodReferences(refs);
    Set<GrantedAuthority> full = new HashSet<>();
    full.add(new SimpleGrantedAuthority("ROLE_USER"));
    full.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
    token.setFullyAuthenticatedAuthorities(full);
    return token;
  }

  private String assertionJson() throws Exception {
    PasskeyTestAuthenticator authenticator = new PasskeyTestAuthenticator(Algorithm.ES256);
    PasskeyAssertionDTO assertion = assertionFor(authenticator,
        PasskeyTestAuthenticator.base64Url(challenge.getValue()), TEST_ORIGIN, false, 1, null);
    return mapper.writeValueAsString(assertion);
  }

  @Test
  void supportsOnlyPasskeyAssertionTokens() {
    assertThat(provider.supports(PasskeyAssertionAuthenticationToken.class), is(true));
    assertThat(provider.supports(ExtendedAuthenticationToken.class), is(false));
    assertThat(provider.supports(UsernamePasswordAuthenticationToken.class), is(false));
  }

  @Test
  void authenticateReturnsNullForOtherTokens() {
    assertThat(provider.authenticate(preAuthenticatedToken()), nullValue());
  }

  @Test
  void authenticateReturnsNullForUnsupportedPreAuthentication() throws Exception {
    PasskeyAssertionAuthenticationToken token = new PasskeyAssertionAuthenticationToken(
        new UsernamePasswordAuthenticationToken(USERNAME, "secret"), assertionJson(), challenge);
    assertThat(provider.authenticate(token), nullValue());
  }

  @Test
  void authenticateUpgradesTokenWhenAssertionIsValid() throws Exception {
    when(accountRepo.findByUsername(USERNAME)).thenReturn(Optional.of(account));
    when(passkeyService.verifyPasskey(eq(account), eq(challenge), any(PasskeyAssertionDTO.class)))
      .thenReturn(new IamPasskey());
    ExtendedAuthenticationToken preAuth = preAuthenticatedToken();

    Authentication result = provider.authenticate(
        new PasskeyAssertionAuthenticationToken(preAuth, assertionJson(), challenge));

    assertThat(result, instanceOf(ExtendedAuthenticationToken.class));
    ExtendedAuthenticationToken full = (ExtendedAuthenticationToken) result;
    assertThat(full.isAuthenticated(), is(true));
    assertThat(full.getName(), equalTo(USERNAME));
    assertThat(full.getAuthorities().stream().map(GrantedAuthority::getAuthority)
      .collect(Collectors.toList()), containsInAnyOrder("ROLE_USER", "ROLE_ADMIN"));
    assertThat(full.getAuthenticationMethodReferences().stream()
      .map(IamAuthenticationMethodReference::getName)
      .collect(Collectors.toList()), containsInAnyOrder("pwd", "hwk"));

    ArgumentCaptor<PasskeyAssertionDTO> captor = ArgumentCaptor.forClass(PasskeyAssertionDTO.class);
    verify(passkeyService).verifyPasskey(eq(account), eq(challenge), captor.capture());
    assertThat(captor.getValue().getResponse().getSignature(), notNullValue());
  }

  @Test
  void authenticateThrowsBadCredentialsWhenAccountNotFound() throws Exception {
    when(accountRepo.findByUsername(USERNAME)).thenReturn(Optional.empty());

    PasskeyAssertionAuthenticationToken token =
        new PasskeyAssertionAuthenticationToken(preAuthenticatedToken(), assertionJson(), challenge);
    assertThrows(BadCredentialsException.class, () -> provider.authenticate(token));
  }

  @Test
  void authenticateThrowsBadCredentialsWhenVerificationFails() throws Exception {
    when(accountRepo.findByUsername(USERNAME)).thenReturn(Optional.of(account));
    when(passkeyService.verifyPasskey(eq(account), eq(challenge), any(PasskeyAssertionDTO.class)))
      .thenThrow(new PasskeyCeremonyException("nope"));

    PasskeyAssertionAuthenticationToken token =
        new PasskeyAssertionAuthenticationToken(preAuthenticatedToken(), assertionJson(), challenge);
    BadCredentialsException e =
        assertThrows(BadCredentialsException.class, () -> provider.authenticate(token));
    assertThat(e.getMessage(), equalTo(MultiFactorPasskeyCheckProvider.BAD_PASSKEY_MESSAGE));
  }

  /**
   * Only AuthenticationExceptions reach the failure handler of the verification filter: a
   * database or an unexpected error must not surface as an error page
   */
  @Test
  void unexpectedErrorsAreReportedAsAuthenticationServiceExceptions() throws Exception {
    when(accountRepo.findByUsername(USERNAME)).thenReturn(Optional.of(account));
    PasskeyAssertionAuthenticationToken token =
        new PasskeyAssertionAuthenticationToken(preAuthenticatedToken(), assertionJson(), challenge);

    when(passkeyService.verifyPasskey(eq(account), eq(challenge), any(PasskeyAssertionDTO.class)))
      .thenThrow(new CannotAcquireLockException("lock wait timeout"));
    AuthenticationServiceException e =
        assertThrows(AuthenticationServiceException.class, () -> provider.authenticate(token));
    assertThat(e.getMessage(),
        equalTo(MultiFactorPasskeyCheckProvider.VERIFICATION_UNAVAILABLE_MESSAGE));
    assertThat(e.getCause(), instanceOf(CannotAcquireLockException.class));

    when(passkeyService.verifyPasskey(eq(account), eq(challenge), any(PasskeyAssertionDTO.class)))
      .thenThrow(new IllegalStateException("corrupt credential data"));
    assertThrows(InternalAuthenticationServiceException.class, () -> provider.authenticate(token));
  }

  @Test
  void authenticateThrowsBadCredentialsWhenAssertionIsMalformed() {
    when(accountRepo.findByUsername(USERNAME)).thenReturn(Optional.of(account));

    for (String bad : new String[] {"", "   ", "not-json", "{}", "{\"id\":\"x\"}",
        "{\"id\":\"x\",\"response\":{\"clientDataJSON\":\"a\"}}"}) {
      PasskeyAssertionAuthenticationToken token =
          new PasskeyAssertionAuthenticationToken(preAuthenticatedToken(), bad, challenge);
      assertThrows(BadCredentialsException.class, () -> provider.authenticate(token));
    }
    verify(passkeyService, never()).verifyPasskey(any(), any(), any());
  }

  @Test
  void tokenExposesWrappedPrincipal() throws Exception {
    ExtendedAuthenticationToken preAuth = preAuthenticatedToken();
    PasskeyAssertionAuthenticationToken token =
        new PasskeyAssertionAuthenticationToken(preAuth, "{}", challenge);

    assertThat(token.getName(), equalTo(USERNAME));
    assertThat(token.getPrincipal(), equalTo(USERNAME));
    assertThat(token.getCredentials(), equalTo("{}"));
    assertThat(token.isAuthenticated(), is(false));
    assertThat(token.getPreAuthentication(), equalTo(preAuth));
    assertThat(token.getChallenge(), equalTo(challenge));
    assertThat(token.getAuthorities().stream().map(GrantedAuthority::getAuthority)
      .collect(Collectors.toList()), empty());
  }
}
