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
package it.infn.mw.iam.test.api.account.multi_factor_authentication.authenticator_app;

import static it.infn.mw.iam.authn.multi_factor_authentication.IamAuthenticationMethodReference.AuthenticationMethodReferenceValues.ONE_TIME_PASSWORD;
import static it.infn.mw.iam.authn.multi_factor_authentication.IamAuthenticationMethodReference.AuthenticationMethodReferenceValues.PASSWORD;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import javax.servlet.http.HttpSession;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.BindingResult;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.account.multi_factor_authentication.IamTotpMfaService;
import it.infn.mw.iam.api.account.multi_factor_authentication.authenticator_app.AuthenticatorAppSettingsController;
import it.infn.mw.iam.api.account.multi_factor_authentication.authenticator_app.CodeDTO;
import it.infn.mw.iam.api.account.multi_factor_authentication.authenticator_app.EnableMfaResponseDTO;
import it.infn.mw.iam.authn.multi_factor_authentication.IamAuthenticationMethodReference;
import it.infn.mw.iam.authn.multi_factor_authentication.MfaVerifyController;
import it.infn.mw.iam.authn.RootIsDashboardSuccessHandler;
import it.infn.mw.iam.authn.oidc.OidcExternalAuthenticationToken;
import it.infn.mw.iam.config.mfa.IamTotpMfaProperties;
import it.infn.mw.iam.core.ExtendedAuthenticationToken;
import it.infn.mw.iam.core.oidc.AuthenticationTimeStamper;
import it.infn.mw.iam.core.web.aup.EnforceAupFilter;
import it.infn.mw.iam.notification.NotificationFactory;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.service.aup.AUPSignatureCheckService;
import it.infn.mw.iam.test.multi_factor_authentication.MultiFactorTestSupport;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Request;

/**
 * Covers the session-upgrade decision in {@code enableAuthenticatorApp} added for
 * https://github.com/indigo-iam/iam/issues/1372: a genuinely pre-authenticated, first-time
 * enrollment should be upgraded to full authentication in place and resume whatever request
 * brought the user to enrollment, while every other caller of this endpoint (a fully authenticated
 * user enrolling voluntarily from the dashboard, an OAuth2 caller, or a pre-authenticated token
 * that is missing what the upgrade needs) must be left exactly as it was before that fix, or sent
 * to {@code /iam/verify} to finish properly instead.
 *
 * <p>
 * Exercises the controller directly rather than through MockMvc: {@code @PreAuthorize} is a proxy
 * concern unrelated to this decision, and (for a PRE_AUTHENTICATED mock token) would otherwise
 * trigger Spring Security's own re-authentication-on-unauthenticated-token behaviour, which is not
 * what is under test here.
 */
@SuppressWarnings("deprecation")
@ExtendWith(MockitoExtension.class)
class EnableAuthenticatorAppSessionUpgradeTests extends MultiFactorTestSupport {

  private static final String AUTHORIZE_PATH = "/authorize";

  @Mock
  private IamTotpMfaService totpMfaService;
  @Mock
  private IamAccountRepository accountRepository;
  @Mock
  private IamTotpMfaProperties iamTotpMfaProperties;
  @Mock
  private NotificationFactory notificationFactory;
  @Mock
  private AUPSignatureCheckService aupSignatureCheckService;
  @Mock
  private ApplicationEventPublisher eventPublisher;

  private AuthenticatorAppSettingsController controller;
  private IamAccount mfaAccount;
  private MockHttpServletRequest request;
  private MockHttpServletResponse response;
  private HttpSession session;
  private CodeDTO code;
  private BindingResult validationResult;

  @BeforeEach
  void setup() {
    Clock clock = Clock.systemUTC();
    mfaAccount = getTotpMfaAccount(clock.instant());

    controller = new AuthenticatorAppSettingsController(totpMfaService, accountRepository,
        iamTotpMfaProperties, notificationFactory, aupSignatureCheckService, eventPublisher,
        new AccountUtils(accountRepository), clock);
    ReflectionTestUtils.setField(controller, "iamBaseUrl", "https://iam.example.org");

    request = new MockHttpServletRequest();
    response = new MockHttpServletResponse();
    session = request.getSession();

    code = new CodeDTO();
    code.setCode("123456");
    validationResult = new BeanPropertyBindingResult(code, "code");

    when(accountRepository.findByUsername(TOTP_USERNAME)).thenReturn(Optional.of(mfaAccount));
    when(totpMfaService.verifyTotp(mfaAccount, "123456")).thenReturn(true);
  }

  @AfterEach
  void tearDown() {
    SecurityContextHolder.clearContext();
  }

  /** Mirrors how a saved request actually lands in the session, instead of asserting the fallback. */
  private String seedSavedAuthorizeRequest() {
    MockHttpServletRequest authorizeRequest = new MockHttpServletRequest("GET", AUTHORIZE_PATH);
    authorizeRequest.setQueryString("client_id=some-client&response_type=code");
    authorizeRequest.setSession(session);
    HttpSessionRequestCache cache = new HttpSessionRequestCache();
    cache.saveRequest(authorizeRequest, response);
    return cache.getRequest(authorizeRequest, response).getRedirectUrl();
  }

  private ExtendedAuthenticationToken localPendingMfaToken(Set<GrantedAuthority> fullAuthorities) {
    ExtendedAuthenticationToken token = new ExtendedAuthenticationToken(TOTP_USERNAME, "secret",
        AuthorityUtils.createAuthorityList("ROLE_PRE_AUTHENTICATED"));
    token.setAuthenticated(false);
    Set<IamAuthenticationMethodReference> refs =
        new HashSet<>(Set.of(new IamAuthenticationMethodReference(PASSWORD.getValue())));
    token.setAuthenticationMethodReferences(refs);
    token.setFullyAuthenticatedAuthorities(fullAuthorities);
    return token;
  }

  @Test
  void pendingMfaAuthenticationIsUpgradedAndResumed() {

    String expectedRedirect = seedSavedAuthorizeRequest();

    ExtendedAuthenticationToken current =
        localPendingMfaToken(new HashSet<>(AuthorityUtils.createAuthorityList("ROLE_USER")));
    SecurityContextHolder.getContext().setAuthentication(current);

    when(aupSignatureCheckService.needsAupSignature(mfaAccount)).thenReturn(false);

    EnableMfaResponseDTO result =
        controller.enableAuthenticatorApp(code, validationResult, session, request, response);

    Authentication upgraded = SecurityContextHolder.getContext().getAuthentication();
    assertTrue(upgraded.isAuthenticated());
    assertTrue(upgraded.getAuthorities().stream()
      .anyMatch(authority -> authority.getAuthority().equals("ROLE_USER")));
    Set<String> amr = ((ExtendedAuthenticationToken) upgraded).getAuthenticationMethodReferences()
      .stream()
      .map(IamAuthenticationMethodReference::getName)
      .collect(Collectors.toSet());
    assertTrue(amr.contains(PASSWORD.getValue()));
    assertTrue(amr.contains(ONE_TIME_PASSWORD.getValue()));

    assertNotNull(session.getAttribute(AuthenticationTimeStamper.AUTH_TIMESTAMP));
    verify(accountRepository).touchLastLoginTimeForUserWithUsername(TOTP_USERNAME);
    verify(eventPublisher).publishEvent(any(InteractiveAuthenticationSuccessEvent.class));

    // The whole point of #1372: resumes the client app's own request, not IAM's dashboard.
    assertEquals(expectedRedirect, result.getRedirectUrl());
  }

  @Test
  void pendingMfaAuthenticationNeedingAupSignatureIsSentThereFirstAndSavedRequestSurvives() {

    seedSavedAuthorizeRequest();

    ExtendedAuthenticationToken current =
        localPendingMfaToken(new HashSet<>(AuthorityUtils.createAuthorityList("ROLE_USER")));
    SecurityContextHolder.getContext().setAuthentication(current);

    when(aupSignatureCheckService.needsAupSignature(mfaAccount)).thenReturn(true);

    EnableMfaResponseDTO result =
        controller.enableAuthenticatorApp(code, validationResult, session, request, response);

    assertTrue(SecurityContextHolder.getContext().getAuthentication().isAuthenticated());
    assertEquals(EnforceAupFilter.AUP_SIGN_PATH, result.getRedirectUrl());
    assertEquals(Boolean.TRUE, session.getAttribute(EnforceAupFilter.REQUESTING_SIGNATURE));

    // The AUP page comes first, but the original request must still be there for
    // AupSignaturePageController to resume once the user actually signs.
    assertNotNull(new HttpSessionRequestCache().getRequest(request, response));
  }

  @Test
  void externalPendingMfaAuthenticationIsUpgraded() {

    // Shaped exactly like OIDCAuthenticationProvider#preAuthenticated: built from the
    // authorities-taking constructor, so isAuthenticated() is true despite holding only
    // ROLE_PRE_AUTHENTICATED -- this is the case the isAuthenticated()-based guard originally
    // missed.
    OidcExternalAuthenticationToken current = new OidcExternalAuthenticationToken(null, null,
        TOTP_USERNAME, null, AuthorityUtils.createAuthorityList("ROLE_PRE_AUTHENTICATED"));
    assertTrue(current.isAuthenticated());
    current.setFullyAuthenticatedAuthorities(
        new HashSet<>(AuthorityUtils.createAuthorityList("ROLE_USER")));
    SecurityContextHolder.getContext().setAuthentication(current);

    when(aupSignatureCheckService.needsAupSignature(mfaAccount)).thenReturn(false);

    EnableMfaResponseDTO result =
        controller.enableAuthenticatorApp(code, validationResult, session, request, response);

    Authentication upgraded = SecurityContextHolder.getContext().getAuthentication();
    assertTrue(upgraded.isAuthenticated());
    assertTrue(upgraded.getAuthorities().stream()
      .anyMatch(authority -> authority.getAuthority().equals("ROLE_USER")));
    verify(accountRepository).touchLastLoginTimeForUserWithUsername(TOTP_USERNAME);
    assertEquals(RootIsDashboardSuccessHandler.DASHBOARD_URL, result.getRedirectUrl());
  }

  @Test
  void pendingMfaAuthenticationWithoutFullAuthoritiesFallsBackToVerify() {

    // Shaped like the X.509 pre-auth token MfaVerifyController#setAuthentication builds: pending
    // MFA, but nothing to upgrade with. Must not be upgraded (would null out authorities) and
    // must not have the saved request resumed on its behalf either (it's still not fully
    // authenticated) -- /iam/verify is the only safe answer.
    ExtendedAuthenticationToken current = localPendingMfaToken(null);
    SecurityContextHolder.getContext().setAuthentication(current);

    EnableMfaResponseDTO result =
        controller.enableAuthenticatorApp(code, validationResult, session, request, response);

    assertSame(current, SecurityContextHolder.getContext().getAuthentication());
    verify(accountRepository, never()).touchLastLoginTimeForUserWithUsername(any());
    verify(eventPublisher, never()).publishEvent(any());
    verify(aupSignatureCheckService, never()).needsAupSignature(any());
    assertEquals(MfaVerifyController.MFA_VERIFY_URL, result.getRedirectUrl());
  }

  @Test
  void rawX509PreAuthenticatedTokenFallsBackToVerify() {

    // Shaped like IamX509AuthenticationUserDetailService: before the user ever visits
    // /iam/verify, the session holds Spring's own PreAuthenticatedAuthenticationToken (not an
    // ExtendedAuthenticationToken), carrying the account's real roles and ROLE_PRE_AUTHENTICATED
    // together on the same principal -- there is no fullyAuthenticatedAuthorities to upgrade
    // with, and this type doesn't match upgradeToFullyAuthenticated anyway.
    User principal = new User(TOTP_USERNAME, "",
        AuthorityUtils.createAuthorityList("ROLE_USER", "ROLE_PRE_AUTHENTICATED"));
    PreAuthenticatedAuthenticationToken current =
        new PreAuthenticatedAuthenticationToken(principal, "", principal.getAuthorities());
    SecurityContextHolder.getContext().setAuthentication(current);

    EnableMfaResponseDTO result =
        controller.enableAuthenticatorApp(code, validationResult, session, request, response);

    assertSame(current, SecurityContextHolder.getContext().getAuthentication());
    verify(accountRepository, never()).touchLastLoginTimeForUserWithUsername(any());
    verify(eventPublisher, never()).publishEvent(any());
    assertEquals(MfaVerifyController.MFA_VERIFY_URL, result.getRedirectUrl());
  }

  @Test
  void alreadyAuthenticatedUserIsNotUpgraded() {

    ExtendedAuthenticationToken current = new ExtendedAuthenticationToken(TOTP_USERNAME, "secret",
        AuthorityUtils.createAuthorityList("ROLE_USER"));
    current.setAuthenticated(true);
    // fullyAuthenticatedAuthorities is deliberately left null here, exactly like a real token
    // built for a user who was never PRE_AUTHENTICATED (see IamLocalAuthenticationProvider) --
    // this is what issue 1372's "skip the page" fix originally got wrong.
    SecurityContextHolder.getContext().setAuthentication(current);

    EnableMfaResponseDTO result =
        controller.enableAuthenticatorApp(code, validationResult, session, request, response);

    Authentication after = SecurityContextHolder.getContext().getAuthentication();
    assertSame(current, after);
    assertTrue(after.getAuthorities().stream()
      .anyMatch(authority -> authority.getAuthority().equals("ROLE_USER")));

    verify(accountRepository, never()).touchLastLoginTimeForUserWithUsername(any());
    verify(eventPublisher, never()).publishEvent(any());
    verify(aupSignatureCheckService, never()).needsAupSignature(any());

    assertEquals(RootIsDashboardSuccessHandler.DASHBOARD_URL, result.getRedirectUrl());
  }

  @Test
  void oAuth2CallerIsNotUpgraded() {

    Authentication userAuthentication = new UsernamePasswordAuthenticationToken(TOTP_USERNAME, "",
        AuthorityUtils.createAuthorityList("ROLE_USER"));
    OAuth2Authentication current =
        new OAuth2Authentication(new MockOAuth2Request("some-client", new String[0]),
            userAuthentication);
    current.setAuthenticated(true);
    SecurityContextHolder.getContext().setAuthentication(current);

    EnableMfaResponseDTO result = assertDoesNotThrow(
        () -> controller.enableAuthenticatorApp(code, validationResult, session, request,
            response));

    assertSame(current, SecurityContextHolder.getContext().getAuthentication());
    verify(accountRepository, never()).touchLastLoginTimeForUserWithUsername(any());
    verify(eventPublisher, never()).publishEvent(any());
    assertEquals(RootIsDashboardSuccessHandler.DASHBOARD_URL, result.getRedirectUrl());
  }
}
