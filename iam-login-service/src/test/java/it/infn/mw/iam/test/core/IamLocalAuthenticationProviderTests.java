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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import it.infn.mw.iam.api.account.multi_factor_authentication.IamTotpMfaService;
import it.infn.mw.iam.authn.multi_factor_authentication.IamAuthenticationMethodReference;
import it.infn.mw.iam.authn.multi_factor_authentication.MultiFactorTotpCheckProvider;
import it.infn.mw.iam.authn.util.Authorities;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.LocalAuthenticationProperties;
import it.infn.mw.iam.config.mfa.IamTotpMfaProperties;
import it.infn.mw.iam.core.ExtendedAuthenticationToken;
import it.infn.mw.iam.core.IamLocalAuthenticationProvider;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.core.user.LoginLockoutResetReason;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamUserInfo;

@SuppressWarnings("deprecation")
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

  private ExtendedAuthenticationToken passwordLoginWithMfa(IamAccount account) {
    UserDetails user = User.withUsername(account.getUsername())
      .password("encoded-password")
      .authorities("ROLE_USER", "ROLE_ADMIN")
      .build();
    when(userDetailsService.loadUserByUsername(account.getUsername())).thenReturn(user);
    when(passwordEncoder.matches("cred", "encoded-password")).thenReturn(true);
    when(iamTotpMfaService.isAuthenticatorAppActive(account)).thenReturn(true);
    return (ExtendedAuthenticationToken) iamLocalAuthenticationProvider
      .authenticate(loginRequest(account.getUsername()));
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

    ExtendedAuthenticationToken request = loginRequest("disabled");

    assertThrows(BadCredentialsException.class,
        () -> iamLocalAuthenticationProvider.authenticate(request));

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

    ExtendedAuthenticationToken request = loginRequest("inactive");

    assertThrows(BadCredentialsException.class,
        () -> iamLocalAuthenticationProvider.authenticate(request));

    verifyNoLockoutMutation();
  }

  @Test
  void suspendedLoginIsMaskedAsBadCredentialsBeforePasswordVerification() {
    IamAccount account = stubAccount("user");

    doThrow(new LockedException("Login is suspended")).when(accountService)
      .checkLoginAllowed(account.getUuid());

    ExtendedAuthenticationToken request = loginRequest("user");

    assertThrows(BadCredentialsException.class,
        () -> iamLocalAuthenticationProvider.authenticate(request));

    verifyNoInteractions(userDetailsService, passwordEncoder);
    verifyNoLockoutMutation();
  }

  @Test
  void disabledAccountFromServiceIsMaskedAsBadCredentials() {
    IamAccount account = stubAccount("user");

    doThrow(new DisabledException("Account is disabled")).when(accountService)
      .checkLoginAllowed(account.getUuid());

    ExtendedAuthenticationToken request = loginRequest("user");

    assertThrows(BadCredentialsException.class,
        () -> iamLocalAuthenticationProvider.authenticate(request));

    verifyNoInteractions(userDetailsService, passwordEncoder);
    verifyNoLockoutMutation();
  }

  @Test
  void internalErrorsAreNotMaskedAsBadCredentials() {
    stubAccount("user");

    IllegalStateException cause = new IllegalStateException("database unavailable");

    when(userDetailsService.loadUserByUsername("user")).thenThrow(cause);

    ExtendedAuthenticationToken request = loginRequest("user");

    InternalAuthenticationServiceException error =
        assertThrows(InternalAuthenticationServiceException.class,
            () -> iamLocalAuthenticationProvider.authenticate(request));

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

  @Test
  void trustedPreauthenticationWithoutMfaAuthoritiesIsStillInitialized() {
    IamAccount account = stubAccount("user");
    var authorities = User.withUsername("user")
      .password("unused")
      .authorities("ROLE_USER")
      .build()
      .getAuthorities();
    ExtendedAuthenticationToken trusted =
        new ExtendedAuthenticationToken("user", null, authorities);
    trusted.setPreAuthenticated(true);
    when(iamTotpMfaService.isAuthenticatorAppActive(account)).thenReturn(true);

    ExtendedAuthenticationToken pending =
        (ExtendedAuthenticationToken) iamLocalAuthenticationProvider.authenticate(trusted);

    assertFalse(pending.isAuthenticated());
    assertTrue(pending.isPreAuthenticated());
    assertEquals(Set.of(Authorities.ROLE_PRE_AUTHENTICATED),
        new HashSet<>(pending.getAuthorities()));
    assertEquals(new HashSet<>(authorities), pending.getFullyAuthenticatedAuthorities());
    verifyNoInteractions(userDetailsService, passwordEncoder);
    verifyNoLockoutMutation();
  }

  @Test
  void verificationPageReauthenticationPreservesAuthoritiesUntilTotpSucceeds() throws Exception {
    IamAccount account = stubAccount("user");
    ExtendedAuthenticationToken pending = passwordLoginWithMfa(account);
    var expectedAuthorities = new HashSet<>(pending.getFullyAuthenticatedAuthorities());
    var expectedReferences = new HashSet<>(pending.getAuthenticationMethodReferences());
    Object expectedDetails = pending.getDetails();

    LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> rules = new LinkedHashMap<>();
    rules.put(AnyRequestMatcher.INSTANCE, SecurityConfig.createList("ROLE_PRE_AUTHENTICATED"));
    FilterSecurityInterceptor interceptor = new FilterSecurityInterceptor();
    interceptor.setAuthenticationManager(new ProviderManager(iamLocalAuthenticationProvider));
    interceptor.setAccessDecisionManager(new AffirmativeBased(List.of(new RoleVoter())));
    interceptor.setSecurityMetadataSource(new DefaultFilterInvocationSecurityMetadataSource(rules));
    interceptor.afterPropertiesSet();

    SecurityContextHolder.clearContext();
    SecurityContextHolder.getContext().setAuthentication(pending);
    try {
      // Include the GET between password and TOTP; repeat it to cover page reloads.
      for (int i = 0; i < 2; i++) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/iam/verify");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);
        interceptor.doFilter(request, response, chain);
        verify(chain).doFilter(request, response);

        assertSame(pending, SecurityContextHolder.getContext().getAuthentication());
        assertFalse(pending.isAuthenticated());
        assertTrue(pending.isPreAuthenticated());
        assertEquals(Set.of(Authorities.ROLE_PRE_AUTHENTICATED),
            new HashSet<>(pending.getAuthorities()));
        assertEquals(expectedAuthorities, pending.getFullyAuthenticatedAuthorities());
        assertEquals(expectedReferences, pending.getAuthenticationMethodReferences());
        assertSame(expectedDetails, pending.getDetails());
      }
      verifyNoLockoutMutation();
      verify(userDetailsService).loadUserByUsername("user");
      verify(passwordEncoder).matches("cred", "encoded-password");

      pending.setTotp("123456");
      when(iamTotpMfaService.verifyTotp(account, "123456")).thenReturn(true);
      Authentication completed =
          new MultiFactorTotpCheckProvider(accountService, iamTotpMfaService).authenticate(pending);

      assertTrue(completed.isAuthenticated());
      assertEquals(expectedAuthorities, new HashSet<>(completed.getAuthorities()));
      assertFalse(completed.getAuthorities().contains(Authorities.ROLE_PRE_AUTHENTICATED));
      assertEquals(Set.of("pwd", "otp"),
          ((ExtendedAuthenticationToken) completed).getAuthenticationMethodReferences()
            .stream()
            .map(IamAuthenticationMethodReference::getName)
            .collect(Collectors.toSet()));
      verify(accountService).resetLoginLockout(account.getUuid(),
          LoginLockoutResetReason.SUCCESSFUL_AUTHENTICATION);
    } finally {
      SecurityContextHolder.clearContext();
    }
  }

  @Test
  void pendingMfaReauthenticationStillRejectsSuspendedAccounts() {
    IamAccount account = stubAccount("user");
    ExtendedAuthenticationToken pending = passwordLoginWithMfa(account);
    doThrow(new LockedException("Login is suspended")).when(accountService)
      .checkLoginAllowed(account.getUuid());

    assertThrows(BadCredentialsException.class,
        () -> iamLocalAuthenticationProvider.authenticate(pending));
    verifyNoLockoutMutation();
  }

  @Test
  void pendingMfaReauthenticationStillRejectsDisabledAccounts() {
    IamAccount account = stubAccount("user");
    ExtendedAuthenticationToken pending = passwordLoginWithMfa(account);
    doThrow(new DisabledException("Account is disabled")).when(accountService)
      .checkLoginAllowed(account.getUuid());

    assertThrows(BadCredentialsException.class,
        () -> iamLocalAuthenticationProvider.authenticate(pending));
    verifyNoLockoutMutation();
  }

  @Test
  void invalidTotpAfterReauthenticationDoesNotGrantFullAuthorities() {
    IamAccount account = stubAccount("user");
    ExtendedAuthenticationToken pending = passwordLoginWithMfa(account);
    ExtendedAuthenticationToken reauthenticated =
        (ExtendedAuthenticationToken) iamLocalAuthenticationProvider.authenticate(pending);
    reauthenticated.setTotp("invalid");
    when(iamTotpMfaService.verifyTotp(account, "invalid")).thenReturn(false);

    MultiFactorTotpCheckProvider provider =
        new MultiFactorTotpCheckProvider(accountService, iamTotpMfaService);
    assertThrows(BadCredentialsException.class, () -> provider.authenticate(reauthenticated));
    assertFalse(reauthenticated.isAuthenticated());
    assertEquals(Set.of(Authorities.ROLE_PRE_AUTHENTICATED),
        new HashSet<>(reauthenticated.getAuthorities()));
    verify(accountService).loginFailedAttempt(account.getUuid());
    verify(accountService, never()).resetLoginLockout(anyString(),
        any(LoginLockoutResetReason.class));
  }
}
