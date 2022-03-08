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
package it.infn.mw.iam.authn.multi_factor_authentication;

import static it.infn.mw.iam.authn.multi_factor_authentication.MfaVerifyController.MFA_VERIFY_URL;
import static it.infn.mw.iam.authn.multi_factor_authentication.MultiFactorVerificationFilter.TOTP_VERIFIED;
import static it.infn.mw.iam.authn.multi_factor_authentication.MultiFactorVerificationFilter.RECOVERY_CODE_VERIFIED;
import static it.infn.mw.iam.authn.multi_factor_authentication.authenticator_app.RecoveryCodeManagementController.RECOVERY_CODE_RESET_URL;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.aup.AUPSignatureCheckService;
import it.infn.mw.iam.authn.EnforceAupSignatureSuccessHandler;
import it.infn.mw.iam.authn.RootIsDashboardSuccessHandler;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

/**
 * Determines if a recovery code was used to authenticate. If so, we need to redirect to the page
 * that asks if the user wants to reset their recovery codes or skip this step to continue onwards.
 */
public class MultiFactorVerificationSuccessHandler implements AuthenticationSuccessHandler {

  private final AccountUtils accountUtils;
  private final AUPSignatureCheckService aupSignatureCheckService;
  private final IamAccountRepository accountRepo;
  private final String iamBaseUrl;

  public MultiFactorVerificationSuccessHandler(AccountUtils accountUtils,
      AUPSignatureCheckService aupSignatureCheckService, IamAccountRepository accountRepo,
      String iamBaseUrl) {
    this.accountUtils = accountUtils;
    this.aupSignatureCheckService = aupSignatureCheckService;
    this.accountRepo = accountRepo;
    this.iamBaseUrl = iamBaseUrl;
  }

  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
      Authentication authentication) throws IOException, ServletException {
    handle(request, response, authentication);
    clearAuthenticationAttributes(request);
  }

  private void handle(HttpServletRequest request, HttpServletResponse response,
      Authentication authentication) throws IOException, ServletException {
    if (response.isCommitted()) {
      System.out
        .println("Response has already been committed. Unable to redirect to " + MFA_VERIFY_URL);
      return;
    } else {
      // If a recovery code was used, RECOVERY_CODE_VERIFIED attribute will exist in the request
      Object recoveryCodeVerifiedAttribute = request.getAttribute(RECOVERY_CODE_VERIFIED);
      if (recoveryCodeVerifiedAttribute != null
          && (boolean) recoveryCodeVerifiedAttribute == Boolean.TRUE) {
        response.sendRedirect(RECOVERY_CODE_RESET_URL);
      } else {
        continueWithDefaultSuccessHandler(request, response, authentication);
      }
    }
  }

  private void continueWithDefaultSuccessHandler(HttpServletRequest request,
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
    request.removeAttribute(TOTP_VERIFIED);
    request.removeAttribute(RECOVERY_CODE_VERIFIED);
  }
}

