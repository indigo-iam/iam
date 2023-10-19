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

import static it.infn.mw.iam.authn.multi_factor_authentication.authenticator_app.RecoveryCodeManagementController.RECOVERY_CODE_RESET_URL;
import static it.infn.mw.iam.authn.multi_factor_authentication.authenticator_app.RecoveryCodeManagementController.RECOVERY_CODE_VIEW_URL;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.log.LogMessage;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.GenericFilterBean;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.account.multi_factor_authentication.IamTotpRecoveryCodeResetService;
import it.infn.mw.iam.api.common.error.NoAuthenticatedUserError;
import it.infn.mw.iam.authn.EnforceAupSignatureSuccessHandler;
import it.infn.mw.iam.authn.RootIsDashboardSuccessHandler;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.service.aup.AUPSignatureCheckService;

/**
 * Filter for handling user response from page that asks user to reset recovery codes or skip this
 * step. This is received through a POST request and then the request is redirected appropriately
 */
public class ResetOrSkipRecoveryCodesFilter extends GenericFilterBean {

  public static final String RESET_KEY = "reset";
  public static final String SKIP_KEY = "skip";
  private static final AntPathRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER =
      new AntPathRequestMatcher(RECOVERY_CODE_RESET_URL, "POST");

  private String resetParameter = RESET_KEY;
  private String skipParameter = SKIP_KEY;

  private final AccountUtils accountUtils;
  private final AUPSignatureCheckService aupSignatureCheckService;
  private final IamAccountRepository accountRepo;
  private final String iamBaseUrl;
  private final IamTotpRecoveryCodeResetService recoveryCodeResetService;

  public ResetOrSkipRecoveryCodesFilter(AccountUtils accountUtils,
      AUPSignatureCheckService aupSignatureCheckService, IamAccountRepository accountRepo,
      String iamBaseUrl, IamTotpRecoveryCodeResetService recoveryCodeResetService) {
    this.accountUtils = accountUtils;
    this.aupSignatureCheckService = aupSignatureCheckService;
    this.accountRepo = accountRepo;
    this.iamBaseUrl = iamBaseUrl;
    this.recoveryCodeResetService = recoveryCodeResetService;
  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
  }

  private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    if (!requiresProcessing(request, response)) {
      chain.doFilter(request, response);
      return;
    }

    String reset = request.getParameter(resetParameter);
    String skip = request.getParameter(skipParameter);

    if (reset != null) {
      // User chose to reset, retrieve authenticated account so we can reset its codes then redirect
      // to the recovery code view page
      IamAccount account =
          accountUtils.getAuthenticatedUserAccount().orElseThrow(NoAuthenticatedUserError::new);
      recoveryCodeResetService.resetRecoveryCodes(account);
      response.sendRedirect(RECOVERY_CODE_VIEW_URL);
    } else if (skip != null) {
      // User chose not to reset, continue with normal success handler
      chain.doFilter(request, response);
      Authentication auth = SecurityContextHolder.getContext().getAuthentication();
      continueWithDefaultSuccessHandler(request, response, auth);
      return;
    } else {
      response.sendError(HttpServletResponse.SC_BAD_REQUEST, "No valid parameter was received");
    }
  }

  private boolean requiresProcessing(HttpServletRequest request, HttpServletResponse response) {
    if (DEFAULT_ANT_PATH_REQUEST_MATCHER.matches(request)) {
      return true;
    }
    if (this.logger.isTraceEnabled()) {
      this.logger
        .trace(LogMessage.format("Did not match request to %s", DEFAULT_ANT_PATH_REQUEST_MATCHER));
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
}
