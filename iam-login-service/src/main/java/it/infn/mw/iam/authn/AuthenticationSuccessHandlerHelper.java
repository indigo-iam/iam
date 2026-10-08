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
package it.infn.mw.iam.authn;

import static it.infn.mw.iam.authn.multi_factor_authentication.MfaVerifyController.MFA_ACTIVATE_URL;
import static it.infn.mw.iam.authn.multi_factor_authentication.MfaVerifyController.MFA_VERIFY_URL;

import java.io.IOException;
import java.time.Clock;
import java.util.Collection;
import java.util.Date;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.account.multi_factor_authentication.IamTotpMfaService;
import it.infn.mw.iam.api.common.NoSuchAccountError;
import it.infn.mw.iam.authn.multi_factor_authentication.MultiFactorTotpCheckProvider;
import it.infn.mw.iam.authn.util.Authorities;
import it.infn.mw.iam.config.mfa.IamTotpMfaProperties;
import it.infn.mw.iam.core.ExtendedAuthenticationToken;
import it.infn.mw.iam.core.oidc.AuthenticationTimeStamper;
import it.infn.mw.iam.core.util.IamAuthenticationLogger;
import it.infn.mw.iam.core.web.aup.EnforceAupFilter;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.service.aup.AUPSignatureCheckService;

public class AuthenticationSuccessHandlerHelper {

  private static final Logger logger =
      LoggerFactory.getLogger(AuthenticationSuccessHandlerHelper.class);

  private final Clock clock;
  private final AccountUtils accountUtils;
  private final String iamBaseUrl;
  private final AUPSignatureCheckService aupSignatureCheckService;
  private final IamAccountRepository accountRepo;
  private final IamTotpMfaService iamTotpMfaService;
  private final IamTotpMfaProperties iamTotpMfaProperties;
  private final ApplicationEventPublisher eventPublisher;
  private final RequestCache requestCache = new HttpSessionRequestCache();

  public AuthenticationSuccessHandlerHelper(Clock clock, AccountUtils accountUtils,
      String iamBaseUrl, AUPSignatureCheckService aupSignatureCheckService,
      IamAccountRepository accountRepo, IamTotpMfaService iamTotpMfaService,
      IamTotpMfaProperties iamTotpMfaProperties, ApplicationEventPublisher eventPublisher) {

    this.clock = clock;
    this.accountUtils = accountUtils;
    this.iamBaseUrl = iamBaseUrl;
    this.aupSignatureCheckService = aupSignatureCheckService;
    this.accountRepo = accountRepo;
    this.iamTotpMfaService = iamTotpMfaService;
    this.iamTotpMfaProperties = iamTotpMfaProperties;
    this.eventPublisher = eventPublisher;
  }

  public void handle(HttpServletRequest request, HttpServletResponse response,
      Authentication authentication) throws IOException, ServletException {
    boolean isPreAuthenticated = isPreAuthenticated(authentication);

    if (response.isCommitted()) {
      logger.warn("Response has already been committed. Unable to redirect to " + MFA_VERIFY_URL);
    } else if (iamTotpMfaProperties.isMultiFactorMandatory() && !isMfaActive(authentication)) {
      response.sendRedirect(MFA_ACTIVATE_URL);
    } else if (isPreAuthenticated) {
      response.sendRedirect(MFA_VERIFY_URL);
    } else {
      continueWithDefaultSuccessHandler(request, response, authentication);
    }
  }

  private boolean isMfaActive(Authentication authentication) {
    final String username = authentication.getName();
    IamAccount account = accountRepo.findByUsername(username)
      .orElseThrow(() -> NoSuchAccountError.forUsername(username));

    return iamTotpMfaService.isAuthenticatorAppActive(account);
  }

  /**
   * If the user account is MFA enabled, the authentication provider would have assigned a role of
   * PRE_AUTHENTICATED at this stage. This function verifies that to determine if we need
   * redirecting to the verification page
   * 
   * @param authentication the user authentication
   * @return true if PRE_AUTHENTICATED
   */
  public boolean isPreAuthenticated(final Authentication authentication) {
    final Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
    for (final GrantedAuthority grantedAuthority : authorities) {
      String authorityName = grantedAuthority.getAuthority();
      if (authorityName.equals(Authorities.ROLE_PRE_AUTHENTICATED.getAuthority())) {
        return true;
      }
    }
    return false;
  }

  /**
   * This calls the normal success handler if the user does not have MFA enabled.
   * 
   * @param request
   * @param response
   * @param auth the user authentication
   * @throws IOException
   * @throws ServletException
   */
  public void continueWithDefaultSuccessHandler(HttpServletRequest request,
      HttpServletResponse response, Authentication auth) throws IOException, ServletException {

    AuthenticationSuccessHandler delegate =
        new RootIsDashboardSuccessHandler(iamBaseUrl, requestCache);

    EnforceAupSignatureSuccessHandler handler = new EnforceAupSignatureSuccessHandler(clock,
        delegate, aupSignatureCheckService, accountUtils, accountRepo);
    handler.onAuthenticationSuccess(request, response, auth);
  }

  public void clearAuthenticationAttributes(HttpServletRequest request) {
    HttpSession session = request.getSession(false);
    if (session == null) {
      return;
    }
    session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
  }

  /**
   * Called once a user finishes first-time TOTP enrollment at
   * {@code /iam/authenticator-app/enable}. Mirrors {@link #handle}/{@link
   * #continueWithDefaultSuccessHandler} for that one case, but returns where to go instead of
   * writing a redirect, since the caller answers with JSON rather than a 302.
   *
   * @param current the authentication in place when enrollment completed
   * @param account the account that just enrolled
   * @return where the client should navigate next
   */
  public String resolveEnrollmentRedirect(Authentication current, IamAccount account,
      HttpSession session, HttpServletRequest request, HttpServletResponse response) {

    if (isPendingMfaUpgrade(current)) {
      Authentication upgraded = MultiFactorTotpCheckProvider.upgradeToFullyAuthenticated(current);
      SecurityContextHolder.getContext().setAuthentication(upgraded);
      clearAuthenticationAttributes(request);

      session.setAttribute(AuthenticationTimeStamper.AUTH_TIMESTAMP, Date.from(clock.instant()));
      IamAuthenticationLogger.INSTANCE.logAuthenticationSuccess(upgraded);
      accountRepo.touchLastLoginTimeForUserWithUsername(account.getUsername());
      eventPublisher.publishEvent(new InteractiveAuthenticationSuccessEvent(upgraded,
          AuthenticationSuccessHandlerHelper.class));

      if (aupSignatureCheckService.needsAupSignature(account)) {
        session.setAttribute(EnforceAupFilter.REQUESTING_SIGNATURE, true);
        return EnforceAupFilter.AUP_SIGN_PATH;
      }
      return resolveSavedRequestOrDashboard(request, response);
    }

    if (isPreAuthenticated(current)) {
      return MFA_VERIFY_URL;
    }

    return resolveSavedRequestOrDashboard(request, response);
  }

  /**
   * True if pending MFA with {@code fullyAuthenticatedAuthorities} to upgrade with; checked by
   * role, not {@code isAuthenticated()}, since external-IdP tokens report authenticated while
   * still pre-auth.
   */
  private boolean isPendingMfaUpgrade(Authentication authentication) {
    if (!isPreAuthenticated(authentication)) {
      return false;
    }
    if (authentication instanceof ExtendedAuthenticationToken token) {
      return token.getFullyAuthenticatedAuthorities() != null;
    }
    if (authentication instanceof AbstractExternalAuthenticationToken<?> token) {
      return token.getFullyAuthenticatedAuthorities() != null;
    }
    return false;
  }

  private String resolveSavedRequestOrDashboard(HttpServletRequest request,
      HttpServletResponse response) {
    SavedRequest savedRequest = requestCache.getRequest(request, response);
    if (savedRequest == null) {
      return RootIsDashboardSuccessHandler.DASHBOARD_URL;
    }

    String redirectUrl = savedRequest.getRedirectUrl();
    if (RootIsDashboardSuccessHandler.redirectsToIamRoot(redirectUrl, iamBaseUrl)) {
      requestCache.removeRequest(request, response);
      return RootIsDashboardSuccessHandler.DASHBOARD_URL;
    }
    return redirectUrl;
  }
}

