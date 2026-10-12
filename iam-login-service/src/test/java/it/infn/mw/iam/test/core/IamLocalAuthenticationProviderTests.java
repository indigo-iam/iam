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

package it.infn.mw.iam.test.core;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import it.infn.mw.iam.api.account.multi_factor_authentication.IamTotpMfaService;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.LocalAuthenticationProperties;
import it.infn.mw.iam.config.mfa.IamTotpMfaProperties;
import it.infn.mw.iam.core.ExtendedAuthenticationToken;
import it.infn.mw.iam.core.IamLocalAuthenticationProvider;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.core.user.LoginLockoutResetReason;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamUserInfo;

@ExtendWith(MockitoExtension.class)
class IamLocalAuthenticationProviderTests {

  @Mock
  IamTotpMfaService iamTotpMfaService;

  @Mock
  IamTotpMfaProperties iamTotpMfaProperties;

  @Mock
  IamProperties properties;

  @Mock
  UserDetailsService userDetailsService;

  @Mock
  PasswordEncoder passwordEncoder;

  @Mock
  IamAccountService accountService;

  @Mock
  LocalAuthenticationProperties localAuthn;

  IamLocalAuthenticationProvider iamLocalAuthenticationProvider;

  @BeforeEach
  void setup() {

    when(properties.getLocalAuthn()).thenReturn(localAuthn);
    when(localAuthn.getEnabledFor()).thenReturn(IamProperties.LocalAuthenticationAllowedUsers.ALL);
    iamLocalAuthenticationProvider =
        new IamLocalAuthenticationProvider(properties, userDetailsService, passwordEncoder,
            accountService, iamTotpMfaService, iamTotpMfaProperties);
  }

  private IamAccount stubAccount(String username) {
    IamAccount account = newAccount(username);
    account.setActive(true);
    when(accountService.findByUsername(username)).thenReturn(Optional.of(account));
    return account;
  }

  private IamAccount newAccount(String username) {
    IamAccount result = new IamAccount();
    result.setUserInfo(new IamUserInfo());
    result.setPassword("secret");
    result.setUsername(username);
    result.setUuid(UUID.randomUUID().toString());
    return result;
  }

  private ExtendedAuthenticationToken loginRequest(String username) {
    return new ExtendedAuthenticationToken(username, "cred");
  }

  private void verifyNoLockoutMutation() {
    verify(accountService, never()).loginFailedAttemptByUsername(anyString());
    verify(accountService, never()).loginFailedAttempt(anyString());
    verify(accountService, never()).resetLoginLockout(anyString(),
        any(LoginLockoutResetReason.class));
  }

  @Test
  void preauthenticatedLoginRequiringMfaSkipsPasswordAuthentication() {
    ExtendedAuthenticationToken token =
        new ExtendedAuthenticationToken("test-user", "test-credentials");
    token.setPreAuthenticated(true);

    IamAccount account = newAccount("test-user");

    when(accountService.findByUsername("test-user")).thenReturn(Optional.of(account));
    when(iamTotpMfaService.isAuthenticatorAppActive(account)).thenReturn(true);

    ExtendedAuthenticationToken result =
        (ExtendedAuthenticationToken) iamLocalAuthenticationProvider.authenticate(token);

    assertFalse(result.isAuthenticated());

    verifyNoInteractions(userDetailsService, passwordEncoder);

    verify(accountService, never()).resetLoginLockout(anyString(),
        any(LoginLockoutResetReason.class));
  }

  @Test
  void disabledAccountFromUserDetailsServiceIsMaskedAsBadCredentials() {
    stubAccount("disabled");

    when(userDetailsService.loadUserByUsername("disabled"))
      .thenThrow(new DisabledException("User 'disabled' is not active."));

    assertThrows(BadCredentialsException.class,
        () -> iamLocalAuthenticationProvider.authenticate(loginRequest("disabled")));

    verifyNoLockoutMutation();
  }

  @Test
  void disabledUserDetailsAreMaskedAsBadCredentials() {
    stubAccount("inactive");

    UserDetails user = User.withUsername("inactive")
      .password("pwd")
      .authorities("ROLE_USER")
      .disabled(true)
      .build();

    when(userDetailsService.loadUserByUsername("inactive")).thenReturn(user);

    assertThrows(BadCredentialsException.class,
        () -> iamLocalAuthenticationProvider.authenticate(loginRequest("inactive")));

    verifyNoLockoutMutation();
  }

  @Test
  void suspendedLoginIsMaskedAsBadCredentialsBeforePasswordVerification() {
    IamAccount account = stubAccount("user");

    doThrow(new LockedException("Login is suspended")).when(accountService)
      .checkLoginAllowed(account.getUuid());

    assertThrows(BadCredentialsException.class,
        () -> iamLocalAuthenticationProvider.authenticate(loginRequest("user")));

    verifyNoInteractions(userDetailsService, passwordEncoder);
    verifyNoLockoutMutation();
  }

  @Test
  void disabledAccountFromServiceIsMaskedAsBadCredentials() {
    IamAccount account = stubAccount("user");

    doThrow(new DisabledException("Account is disabled")).when(accountService)
      .checkLoginAllowed(account.getUuid());

    assertThrows(BadCredentialsException.class,
        () -> iamLocalAuthenticationProvider.authenticate(loginRequest("user")));

    verifyNoInteractions(userDetailsService, passwordEncoder);
    verifyNoLockoutMutation();
  }

  @Test
  void internalErrorsAreNotMaskedAsBadCredentials() {
    stubAccount("user");

    IllegalStateException cause = new IllegalStateException("database unavailable");

    when(userDetailsService.loadUserByUsername("user")).thenThrow(cause);

    InternalAuthenticationServiceException error =
        assertThrows(InternalAuthenticationServiceException.class,
            () -> iamLocalAuthenticationProvider.authenticate(loginRequest("user")));

    assertSame(cause, error.getCause());
    verifyNoLockoutMutation();
  }

  @Test
  void successfulPasswordLoginWithoutMfaResetsLockout() {
    IamAccount account = stubAccount("user");

    UserDetails user =
        User.withUsername("user").password("encoded-password").authorities("ROLE_USER").build();

    when(userDetailsService.loadUserByUsername("user")).thenReturn(user);
    when(passwordEncoder.matches("cred", "encoded-password")).thenReturn(true);

    // Both MFA mocks return false by default.
    Authentication result = iamLocalAuthenticationProvider.authenticate(loginRequest("user"));

    assertTrue(result.isAuthenticated());

    verify(accountService).resetLoginLockout(account.getUuid(),
        LoginLockoutResetReason.SUCCESSFUL_AUTHENTICATION);

    verify(accountService, never()).loginFailedAttemptByUsername(anyString());
  }

  @Test
  void preauthenticatedLoginRequiringMfaDoesNotVerifyPasswordOrResetLockout() {
    IamAccount account = stubAccount("user");
    ExtendedAuthenticationToken request = loginRequest("user");
    request.setPreAuthenticated(true);

    when(iamTotpMfaService.isAuthenticatorAppActive(account)).thenReturn(true);

    Authentication result = iamLocalAuthenticationProvider.authenticate(request);

    assertFalse(result.isAuthenticated());
    assertTrue(result.getAuthorities()
      .stream()
      .anyMatch(a -> "ROLE_PRE_AUTHENTICATED".equals(a.getAuthority())));

    verifyNoInteractions(userDetailsService, passwordEncoder);
    verifyNoLockoutMutation();
  }
}
