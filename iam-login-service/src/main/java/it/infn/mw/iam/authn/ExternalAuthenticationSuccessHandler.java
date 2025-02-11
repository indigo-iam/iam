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

import static it.infn.mw.iam.authn.multi_factor_authentication.MfaVerifyController.MFA_VERIFY_URL;

import java.io.IOException;
import java.util.Collection;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.authn.util.Authorities;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.service.aup.AUPSignatureCheckService;

public class ExternalAuthenticationSuccessHandler extends ExternalAuthenticationHandlerSupport
    implements AuthenticationSuccessHandler {

  private static final Logger logger =
      LoggerFactory.getLogger(ExternalAuthenticationSuccessHandler.class);

  private final String unregisteredUserTargetURL;
  private final AccountUtils accountUtils;
  private final String iamBaseUrl;
  private final AUPSignatureCheckService aupSignatureCheckService;
  private final IamAccountRepository accountRepo;

  public ExternalAuthenticationSuccessHandler(String unregisteredUserTargetURL,
      AccountUtils accountUtils, String iamBaseUrl,
      AUPSignatureCheckService aupSignatureCheckService, IamAccountRepository accountRepo) {
    this.unregisteredUserTargetURL = unregisteredUserTargetURL;
    this.accountUtils = accountUtils;
    this.iamBaseUrl = iamBaseUrl;
    this.aupSignatureCheckService = aupSignatureCheckService;
    this.accountRepo = accountRepo;
  }

  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
      Authentication authentication) throws IOException, ServletException {

    if (hasOngoingAccountLinking(request)) {

      HttpSession session = request.getSession();

      saveExternalAuthenticationInSession(session, authentication);
      restoreSavedAuthentication(session);
      setAccountLinkingDone(session);

      request.getRequestDispatcher(getAccountLinkingForwardTarget(request))
        .forward(request, response);

    } else {

      if (isExternalUnregisteredUser(authentication)) {
        response.sendRedirect(unregisteredUserTargetURL);

      } else {
        handle(request, response, authentication);
        clearAuthenticationAttributes(request);
      }

    }
  }

  protected void handle(HttpServletRequest request, HttpServletResponse response,
      Authentication authentication) throws IOException, ServletException {
    boolean isPreAuthenticated = isPreAuthenticated(authentication);

    if (response.isCommitted()) {
      logger.warn("Response has already been committed. Unable to redirect to " + MFA_VERIFY_URL);
    } else if (isPreAuthenticated) {
      response.sendRedirect(MFA_VERIFY_URL);
    } else {
      continueWithDefaultSuccessHandler(request, response, authentication);
    }
  }

  protected boolean isPreAuthenticated(final Authentication authentication) {
    final Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
    for (final GrantedAuthority grantedAuthority : authorities) {
      String authorityName = grantedAuthority.getAuthority();
      if (authorityName.equals(Authorities.ROLE_PRE_AUTHENTICATED.getAuthority())) {
        return true;
      }
    }

    return false;
  }

  protected void continueWithDefaultSuccessHandler(HttpServletRequest request,
      HttpServletResponse response, Authentication auth) throws IOException, ServletException {

    AuthenticationSuccessHandler delegate =
        new RootIsDashboardSuccessHandler(iamBaseUrl, new HttpSessionRequestCache());

    EnforceAupSignatureSuccessHandler handler = new EnforceAupSignatureSuccessHandler(delegate,
        aupSignatureCheckService, accountUtils, accountRepo);
    handler.onAuthenticationSuccess(request, response, auth);
  }

  protected void clearAuthenticationAttributes(HttpServletRequest request) {
    HttpSession session = request.getSession(false);
    if (session == null) {
      return;
    }
    session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
  }

}
