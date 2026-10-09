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
package it.infn.mw.iam.test.ext_authn;

import static it.infn.mw.iam.authn.multi_factor_authentication.IamAuthenticationMethodReference.AuthenticationMethodReferenceValues.ONE_TIME_PASSWORD;
import static it.infn.mw.iam.authn.multi_factor_authentication.IamAuthenticationMethodReference.AuthenticationMethodReferenceValues.PASSWORD;
import static it.infn.mw.iam.authn.multi_factor_authentication.IamAuthenticationMethodReference.AuthenticationMethodReferenceValues.X509;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.util.HashSet;
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
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.account.multi_factor_authentication.IamTotpMfaService;
import it.infn.mw.iam.authn.AuthenticationSuccessHandlerHelper;
import it.infn.mw.iam.authn.RootIsDashboardSuccessHandler;
import it.infn.mw.iam.authn.multi_factor_authentication.IamAuthenticationMethodReference;
import it.infn.mw.iam.authn.multi_factor_authentication.MfaVerifyController;
import it.infn.mw.iam.authn.oidc.OidcExternalAuthenticationToken;
import it.infn.mw.iam.authn.util.Authorities;
import it.infn.mw.iam.config.mfa.IamTotpMfaProperties;
import it.infn.mw.iam.core.ExtendedAuthenticationToken;
import it.infn.mw.iam.core.oidc.AuthenticationTimeStamper;
import it.infn.mw.iam.core.web.aup.EnforceAupFilter;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.service.aup.AUPSignatureCheckService;
import it.infn.mw.iam.test.multi_factor_authentication.MultiFactorTestSupport;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Request;

@SuppressWarnings("deprecation")
@ExtendWith(MockitoExtension.class)
class AuthenticationSuccessHandlerHelperEnrollmentRedirectTests extends MultiFactorTestSupport {

  private static final String AUTHORIZE_PATH = "/authorize";
  private static final String IAM_BASE_URL = "https://iam.example.org";

  @Mock
  private AccountUtils accountUtils;

  @Mock
  private AUPSignatureCheckService aupSignatureCheckService;

  @Mock
  private IamAccountRepository accountRepository;

  @Mock
  private IamTotpMfaService iamTotpMfaService;

  @Mock
  private IamTotpMfaProperties iamTotpMfaProperties;

  @Mock
  private ApplicationEventPublisher eventPublisher;

  @Mock
  private SessionAuthenticationStrategy sessionAuthenticationStrategy;

  private AuthenticationSuccessHandlerHelper helper;
  private IamAccount mfaAccount;
  private MockHttpServletRequest request;
  private MockHttpServletResponse response;
  private HttpSession session;

  @BeforeEach
  void setup() {
    Clock clock = Clock.systemUTC();
    mfaAccount = getTotpMfaAccount(clock.instant());

    helper = new AuthenticationSuccessHandlerHelper(clock, accountUtils, IAM_BASE_URL,
        aupSignatureCheckService, accountRepository, iamTotpMfaService, iamTotpMfaProperties,
        eventPublisher, sessionAuthenticationStrategy);

    request = new MockHttpServletRequest();
    response = new MockHttpServletResponse();
    session = request.getSession();
  }

  @AfterEach
  void tearDown() {
    SecurityContextHolder.clearContext();
  }

  /**
   * Mirrors how a saved request actually lands in the session, instead of asserting the fallback.
   */
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

    when(aupSignatureCheckService.needsAupSignature(mfaAccount)).thenReturn(false);

    String redirectUrl =
        helper.resolveEnrollmentRedirect(current, mfaAccount, session, request, response);

    Authentication upgraded = SecurityContextHolder.getContext().getAuthentication();
    assertTrue(upgraded.isAuthenticated());
    assertTrue(upgraded.getAuthorities()
      .stream()
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

    // Resume the client app's own request, not IAM dashboard.
    assertEquals(expectedRedirect, redirectUrl);
  }

  @Test
  void pendingMfaAuthenticationNeedingAupSignatureIsSentThereFirstAndSavedRequestSurvives() {

    seedSavedAuthorizeRequest();

    ExtendedAuthenticationToken current =
        localPendingMfaToken(new HashSet<>(AuthorityUtils.createAuthorityList("ROLE_USER")));

    when(aupSignatureCheckService.needsAupSignature(mfaAccount)).thenReturn(true);

    String redirectUrl =
        helper.resolveEnrollmentRedirect(current, mfaAccount, session, request, response);

    assertTrue(SecurityContextHolder.getContext().getAuthentication().isAuthenticated());
    assertEquals(EnforceAupFilter.AUP_SIGN_PATH, redirectUrl);
    assertEquals(Boolean.TRUE, session.getAttribute(EnforceAupFilter.REQUESTING_SIGNATURE));

    // The AUP page comes first, but the original request must still be there for
    // AupSignaturePageController to resume once the user actually signs.
    assertNotNull(new HttpSessionRequestCache().getRequest(request, response));
  }

  @Test
  void externalPendingMfaAuthenticationIsUpgraded() {

    OidcExternalAuthenticationToken current = new OidcExternalAuthenticationToken(null, null,
        TOTP_USERNAME, null, AuthorityUtils.createAuthorityList("ROLE_PRE_AUTHENTICATED"));
    assertTrue(current.isAuthenticated());
    current.setFullyAuthenticatedAuthorities(
        new HashSet<>(AuthorityUtils.createAuthorityList("ROLE_USER")));

    when(aupSignatureCheckService.needsAupSignature(mfaAccount)).thenReturn(false);

    String redirectUrl =
        helper.resolveEnrollmentRedirect(current, mfaAccount, session, request, response);

    Authentication upgraded = SecurityContextHolder.getContext().getAuthentication();
    assertTrue(upgraded.isAuthenticated());
    assertTrue(upgraded.getAuthorities()
      .stream()
      .anyMatch(authority -> authority.getAuthority().equals("ROLE_USER")));
    verify(accountRepository).touchLastLoginTimeForUserWithUsername(TOTP_USERNAME);
    assertEquals(RootIsDashboardSuccessHandler.DASHBOARD_URL, redirectUrl);
  }

  @Test
  void pendingMfaAuthenticationWithoutFullAuthoritiesFallsBackToVerify() {

    ExtendedAuthenticationToken current = localPendingMfaToken(null);
    SecurityContextHolder.getContext().setAuthentication(current);

    String redirectUrl =
        helper.resolveEnrollmentRedirect(current, mfaAccount, session, request, response);

    // Left exactly as the caller had it -- nothing safe to upgrade to here.
    assertSame(current, SecurityContextHolder.getContext().getAuthentication());
    verify(accountRepository, never()).touchLastLoginTimeForUserWithUsername(any());
    verify(eventPublisher, never()).publishEvent(any());
    verify(aupSignatureCheckService, never()).needsAupSignature(any());
    assertEquals(MfaVerifyController.MFA_VERIFY_URL, redirectUrl);
  }

  @Test
  void rawX509PreAuthenticatedTokenIsUpgradedToFullyAuthenticated() {

    User principal = new User(TOTP_USERNAME, "",
        AuthorityUtils.createAuthorityList("ROLE_USER", "ROLE_PRE_AUTHENTICATED"));
    PreAuthenticatedAuthenticationToken current =
        new PreAuthenticatedAuthenticationToken(principal, "", principal.getAuthorities());
    SecurityContextHolder.getContext().setAuthentication(current);

    String redirectUrl =
        helper.resolveEnrollmentRedirect(current, mfaAccount, session, request, response);

    Authentication updated = SecurityContextHolder.getContext().getAuthentication();

    assertInstanceOf(ExtendedAuthenticationToken.class, updated);
    assertTrue(updated.isAuthenticated());

    assertFalse(updated.getAuthorities()
      .stream()
      .anyMatch(authority -> Authorities.ROLE_PRE_AUTHENTICATED.getAuthority()
        .equals(authority.getAuthority())));

    ExtendedAuthenticationToken token = (ExtendedAuthenticationToken) updated;

    assertTrue(token.getAuthenticationMethodReferences()
      .stream()
      .anyMatch(ref -> X509.getValue().equals(ref.getName())));

    assertTrue(token.getAuthenticationMethodReferences()
      .stream()
      .anyMatch(ref -> ONE_TIME_PASSWORD.getValue().equals(ref.getName())));

    assertNotEquals(MfaVerifyController.MFA_VERIFY_URL, redirectUrl);
  }

  @Test
  void alreadyAuthenticatedUserIsNotUpgraded() {

    ExtendedAuthenticationToken current = new ExtendedAuthenticationToken(TOTP_USERNAME, "secret",
        AuthorityUtils.createAuthorityList("ROLE_USER"));
    current.setAuthenticated(true);

    SecurityContextHolder.getContext().setAuthentication(current);

    String redirectUrl =
        helper.resolveEnrollmentRedirect(current, mfaAccount, session, request, response);

    assertSame(current, SecurityContextHolder.getContext().getAuthentication());

    verify(accountRepository, never()).touchLastLoginTimeForUserWithUsername(any());
    verify(eventPublisher, never()).publishEvent(any());
    verify(aupSignatureCheckService, never()).needsAupSignature(any());

    assertEquals(RootIsDashboardSuccessHandler.DASHBOARD_URL, redirectUrl);
  }

  @Test
  void oAuth2CallerIsNotUpgraded() {

    Authentication userAuthentication = new UsernamePasswordAuthenticationToken(TOTP_USERNAME, "",
        AuthorityUtils.createAuthorityList("ROLE_USER"));
    OAuth2Authentication current = new OAuth2Authentication(
        new MockOAuth2Request("some-client", new String[0]), userAuthentication);
    current.setAuthenticated(true);
    SecurityContextHolder.getContext().setAuthentication(current);

    String redirectUrl = assertDoesNotThrow(
        () -> helper.resolveEnrollmentRedirect(current, mfaAccount, session, request, response));

    assertSame(current, SecurityContextHolder.getContext().getAuthentication());
    verify(accountRepository, never()).touchLastLoginTimeForUserWithUsername(any());
    verify(eventPublisher, never()).publishEvent(any());
    assertEquals(RootIsDashboardSuccessHandler.DASHBOARD_URL, redirectUrl);
  }
}
