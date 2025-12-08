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
package it.infn.mw.iam.core.web.multi_factor_authentication;

import static java.util.Objects.isNull;

import java.io.IOException;
import java.util.Optional;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.aup.error.AupNotFoundError;
import it.infn.mw.iam.api.common.NoSuchAccountError;
import it.infn.mw.iam.config.mfa.IamTotpMfaProperties;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAup;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAupRepository;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;
import it.infn.mw.iam.service.aup.AUPSignatureCheckService;


public class EnforceMfaFilter implements Filter {

  public static final Logger LOG = LoggerFactory.getLogger(EnforceMfaFilter.class);

  public static final String MFA_API_PATH = "/iam/mfa";
  public static final String ENABLE_MFA_PATH = "/iam/authenticator-app/enable";
  public static final String ACTIVATE_MFA_PATH = "/iam/mfa/acivate";
  public static final String ACTIVATE_MFA_JSP = "activateMfa.jsp";

  public static final String REQUESTING_MFA = "iam.mfa.requesting-mfa";

  final AUPSignatureCheckService signatureCheckService;
  final AccountUtils accountUtils;
  private final IamTotpMfaRepository totpMfaRepository;
  private final IamTotpMfaProperties iamTotpMfaProperties;


  public EnforceMfaFilter(AUPSignatureCheckService signatureCheckService, AccountUtils accountUtils,
      IamTotpMfaRepository totpMfaRepository, IamTotpMfaProperties iamTotpMfaProperties) {
    this.signatureCheckService = signatureCheckService;
    this.accountUtils = accountUtils;
    this.totpMfaRepository = totpMfaRepository;
    this.iamTotpMfaProperties = iamTotpMfaProperties;
  }

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    // Empty method
  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {

    HttpServletRequest req = (HttpServletRequest) request;
    HttpServletResponse res = (HttpServletResponse) response;

    HttpSession session = req.getSession(false);

    String requestURL = req.getRequestURL().toString();

    if (!accountUtils.isAuthenticated() || isNull(session) || !iamTotpMfaProperties.isMultiFactorMandatory()
        || requestURL.endsWith(MFA_API_PATH)) {
      chain.doFilter(request, response);
      return;
    }

    Optional<IamAccount> authenticatedUser = accountUtils.getAuthenticatedUserAccount();

    if (!authenticatedUser.isPresent()) {
      chain.doFilter(request, response);
      return;
    }

    if (!isNull(session.getAttribute(REQUESTING_MFA))) {
      if (requestURL.endsWith(ENABLE_MFA_PATH) || requestURL.endsWith(ACTIVATE_MFA_PATH)
          || requestURL.endsWith(ACTIVATE_MFA_JSP)) {
        chain.doFilter(request, response);
        return;
      }
      if (!res.isCommitted()) {
        res.sendRedirect(ACTIVATE_MFA_PATH);
      }
      return;
    }

    if (!isMfaActive() && !res.isCommitted()) {

      session.setAttribute(REQUESTING_MFA, true);
      res.sendRedirect(ACTIVATE_MFA_PATH);
      return;

    }

    chain.doFilter(request, response);
  }

   private boolean isMfaActive() {
    Optional<IamAccount> authenticatedUser = accountUtils.getAuthenticatedUserAccount();

    Optional<IamTotpMfa> totpMfaOptional = totpMfaRepository.findByAccount(authenticatedUser.get());
    if (totpMfaOptional.isPresent()) {
      return totpMfaOptional.get().isActive();
    }
    return false;
  }

  @Override
  public void destroy() {
    // Empty method
  }

}
