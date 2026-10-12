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
package it.infn.mw.iam.test.multi_factor_authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import it.infn.mw.iam.api.account.multi_factor_authentication.IamTotpMfaService;
import it.infn.mw.iam.authn.multi_factor_authentication.IamAuthenticationMethodReference;
import it.infn.mw.iam.authn.multi_factor_authentication.MultiFactorTotpCheckProvider;
import it.infn.mw.iam.authn.oidc.OidcExternalAuthenticationToken;
import it.infn.mw.iam.authn.saml.SamlExternalAuthenticationToken;
import it.infn.mw.iam.core.ExtendedAuthenticationToken;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.core.user.LoginLockoutResetReason;
import it.infn.mw.iam.core.user.exception.MfaSecretNotFoundException;
import it.infn.mw.iam.persistence.model.IamAccount;

@ExtendWith(MockitoExtension.class)
class MultiFactorTotpCheckProviderTests extends IamTotpMfaServiceTestSupport {

  private MultiFactorTotpCheckProvider multiFactorTotpCheckProvider;

  @Mock
  private IamAccountService accountService;

  @Mock
  private IamTotpMfaService totpMfaService;

  @Mock
  private ExtendedAuthenticationToken token;

  @Mock
  private OidcExternalAuthenticationToken oidcToken;

  @Mock
  private SamlExternalAuthenticationToken samlToken;

  Clock clock;

  @BeforeEach
  void setup() {

    clock = Clock.systemUTC();
    MockitoAnnotations.openMocks(this);
    multiFactorTotpCheckProvider = new MultiFactorTotpCheckProvider(accountService, totpMfaService);
  }

  @Test
  void authenticateReturnsNullWhenTotpIsNull() {
    when(token.getTotp()).thenReturn(null);
    assertNull(multiFactorTotpCheckProvider.authenticate(token));
    verify(accountService, never()).checkLoginAllowed(anyString());
  }

  @Test
  void authenticateDoesntCheckLockoutBeforeAccountLookup() {
    when(token.getTotp()).thenReturn("123456");
    when(token.getName()).thenReturn("username");
    when(accountService.findByUsername("username")).thenReturn(Optional.empty());

    assertThrows(BadCredentialsException.class,
        () -> multiFactorTotpCheckProvider.authenticate(token));
    verify(accountService, never()).checkLoginAllowed(anyString());
  }

  @Test
  void authenticatePropagatesMfaSecretNotFoundException() {
    IamAccount account = getAccount(clock.instant());
    account.setActive(true);
    when(token.getName()).thenReturn("totp");
    when(token.getTotp()).thenReturn("123456");
    when(accountService.findByUsername("totp")).thenReturn(Optional.of(account));
    when(totpMfaService.verifyTotp(account, "123456"))
      .thenThrow(new MfaSecretNotFoundException("Mfa secret not found"));

    assertThrows(MfaSecretNotFoundException.class,
        () -> multiFactorTotpCheckProvider.authenticate(token));
  }

  @Test
  void authenticateThrowsBadCredentialsExceptionWhenTotpIsInvalid() {
    IamAccount account = getAccount(clock.instant());
    account.setActive(true);
    when(token.getName()).thenReturn("totp");
    when(token.getTotp()).thenReturn("123456");
    when(accountService.findByUsername(anyString())).thenReturn(Optional.of(account));
    when(totpMfaService.verifyTotp(account, "123456")).thenReturn(false);

    BadCredentialsException e = assertThrows(BadCredentialsException.class,
        () -> multiFactorTotpCheckProvider.authenticate(token));
    assertEquals("Bad TOTP", e.getMessage());

    verify(accountService).loginFailedAttempt(account.getUuid());
    verify(accountService, never()).resetLoginLockout(anyString(), any());
  }

  @Test
  void authenticateResetsLockoutWhenTotpIsValid() {
    IamAccount account = getAccount(clock.instant());
    account.setActive(true);
    when(token.getName()).thenReturn("totp");
    when(token.getTotp()).thenReturn("123456");
    when(accountService.findByUsername("totp")).thenReturn(Optional.of(account));
    when(totpMfaService.verifyTotp(account, "123456")).thenReturn(true);

    assertNotNull(multiFactorTotpCheckProvider.authenticate(token));

    verify(accountService).checkLoginAllowed(account.getUuid());
    verify(accountService).resetLoginLockout(eq(account.getUuid()),
        eq(LoginLockoutResetReason.SUCCESSFUL_AUTHENTICATION));
    verify(accountService, never()).loginFailedAttempt(anyString());
  }

  @Test
  void authenticateRejectsDisabledAccountWithGenericFailure() {
    IamAccount account = getAccount(clock.instant());
    account.setActive(false);
    when(token.getName()).thenReturn("totp");
    when(token.getTotp()).thenReturn("999999");
    when(accountService.findByUsername("totp")).thenReturn(Optional.of(account));

    BadCredentialsException e = assertThrows(BadCredentialsException.class,
        () -> multiFactorTotpCheckProvider.authenticate(token));
    assertEquals("Bad TOTP", e.getMessage());
    verify(accountService).loginFailedAttempt(eq(account.getUuid()));
  }

  @Test
  void authenticateMasksLockoutAsBadCredentialsWhenSuspended() {
    when(token.getTotp()).thenReturn("123456");
    when(token.getName()).thenReturn("locked");
    IamAccount account = getAccount(clock.instant());
    account.setActive(true);
    when(accountService.findByUsername("locked")).thenReturn(Optional.of(account));
    doThrow(new LockedException("Bad credentials")).when(accountService)
      .checkLoginAllowed(account.getUuid());

    LockedException e = assertThrows(LockedException.class,
        () -> multiFactorTotpCheckProvider.authenticate(token));
    assertEquals("Bad credentials", e.getMessage());
    verify(accountService, never()).loginFailedAttempt(eq("locked"));
  }

  @Test
  void authenticateWithOidcTokenReturnsSuccessfulAuthenticationWhenTotpIsValid() {
    IamAccount account = getAccount(clock.instant());
    account.setActive(true);
    when(oidcToken.getName()).thenReturn("totp");
    when(oidcToken.getTotp()).thenReturn("123456");
    when(accountService.findByUsername("totp")).thenReturn(Optional.of(account));
    when(totpMfaService.verifyTotp(account, "123456")).thenReturn(true);

    assertNotNull(multiFactorTotpCheckProvider.authenticate(oidcToken));
  }

  @Test
  void authenticateWithSamlTokenReturnsSuccessfulAuthenticationWhenTotpIsValid() {
    IamAccount account = getAccount(clock.instant());
    account.setActive(true);
    when(samlToken.getName()).thenReturn("totp");
    when(samlToken.getTotp()).thenReturn("123456");
    when(accountService.findByUsername("totp")).thenReturn(Optional.of(account));
    when(totpMfaService.verifyTotp(account, "123456")).thenReturn(true);

    assertNotNull(multiFactorTotpCheckProvider.authenticate(samlToken));
  }

  @Test
  void preserveExternalAuthnAfterMfa() {
    OidcExternalAuthenticationToken externalToken = mock(OidcExternalAuthenticationToken.class);

    Set<IamAuthenticationMethodReference> refs = new HashSet<>();
    Set<GrantedAuthority> authorities = Set.of(new SimpleGrantedAuthority("ROLE_USER"));

    when(externalToken.getTotp()).thenReturn("123456");
    when(externalToken.getAuthenticationMethodReferences()).thenReturn(refs);
    when(externalToken.getFullyAuthenticatedAuthorities()).thenReturn(new HashSet<>(authorities));
    when(externalToken.getName()).thenReturn("test-user");
    when(externalToken.getPrincipal()).thenReturn("test-user");
    when(externalToken.getCredentials()).thenReturn("credentials");

    IamAccount account = getAccount(clock.instant());
    when(accountService.findByUsername("test-user")).thenReturn(Optional.of(account));
    when(totpMfaService.verifyTotp(account, "123456")).thenReturn(true);

    Authentication result = multiFactorTotpCheckProvider.authenticate(externalToken);
    assertThat(result).isInstanceOf(ExtendedAuthenticationToken.class);

    ExtendedAuthenticationToken extended = (ExtendedAuthenticationToken) result;
    assertThat(extended.getExternalAuthentication()).isSameAs(externalToken);
  }

  @Test
  void externalAuthnIsNullWhenLocalUserWithMfa() {
    Set<GrantedAuthority> authorities = Set.of(new SimpleGrantedAuthority("ROLE_USER"));

    ExtendedAuthenticationToken authentication =
        new ExtendedAuthenticationToken("test-user", "credentials", authorities);

    authentication.setTotp("123456");
    authentication.setFullyAuthenticatedAuthorities(authorities);

    IamAccount account = getAccount(clock.instant());
    when(accountService.findByUsername("test-user")).thenReturn(Optional.of(account));
    when(totpMfaService.verifyTotp(account, "123456")).thenReturn(true);

    Authentication result = multiFactorTotpCheckProvider.authenticate(authentication);
    assertThat(result).isInstanceOf(ExtendedAuthenticationToken.class);

    ExtendedAuthenticationToken extended = (ExtendedAuthenticationToken) result;
    assertThat(extended.getExternalAuthentication()).isNull();
  }
}
