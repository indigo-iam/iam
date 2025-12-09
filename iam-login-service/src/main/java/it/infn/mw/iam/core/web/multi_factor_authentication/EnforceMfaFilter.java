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

import java.io.IOException;
import java.util.Optional;
import java.util.Set;

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
import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.config.mfa.IamTotpMfaProperties;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;

public class EnforceMfaFilter implements Filter {

  public static final Logger LOG = LoggerFactory.getLogger(EnforceMfaFilter.class);

  public static final String MFA_API_PATH = "/iam/mfa";
  public static final String ENABLE_MFA_PATH = "/iam/authenticator-app/enable";
  public static final String ACTIVATE_MFA_PATH = "/iam/mfa/acivate";
  public static final String ACTIVATE_MFA_JSP = "activateMfa.jsp";

  private static final Set<String> ALLOWLIST_EXACT = Set.of(
      ENABLE_MFA_PATH,
      ACTIVATE_MFA_PATH,
      MFA_API_PATH);

  private static final Set<String> ALLOWLIST_PREFIXES = Set.of(
      "/login",
      "/logout",
      "/css/",
      "/js/",
      "/images/",
      "/webjars/");

  public static final String REQUESTING_MFA = "iam.mfa.requesting-mfa";
  public static final String POST_MFA_TARGET = "POST_MFA_TARGET";

  private final AccountUtils accountUtils;
  private final IamTotpMfaRepository totpMfaRepository;
  private final IamTotpMfaProperties iamTotpMfaProperties;

  public EnforceMfaFilter(AccountUtils accountUtils,
      IamTotpMfaRepository totpMfaRepository, IamTotpMfaProperties iamTotpMfaProperties) {
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

    final String path = req.getRequestURI();

    if (isAllowListed(path)) {
      chain.doFilter(req, res);
      return;
    }

    final boolean mfaMandatory = iamTotpMfaProperties.isMultiFactorMandatory();
    if (!mfaMandatory) {
      chain.doFilter(req, res);
      return;
    }

    final boolean authenticated = accountUtils.isAuthenticated();
    if (!authenticated) {
      chain.doFilter(req, res);
      return;
    }

    Optional<IamAccount> authenticatedUserOpt = accountUtils.getAuthenticatedUserAccount();
    if (authenticatedUserOpt.isEmpty()) {
      chain.doFilter(req, res);
      return;
    }

    HttpSession session = req.getSession(false);
    final boolean sessionExists = (session != null);
    if (!sessionExists) {
      chain.doFilter(req, res);
      return;
    }

    final boolean requestingMfa = Boolean.TRUE.equals(session.getAttribute(REQUESTING_MFA));
    if (requestingMfa) {
      if (isMfaFlowPath(path)) {
        chain.doFilter(req, res);
        return;
      }

      if (!res.isCommitted()) {
        res.sendRedirect(ACTIVATE_MFA_PATH);
      }
      return;
    }

    if (!isMfaActive(authenticatedUserOpt)) {
      session.setAttribute(REQUESTING_MFA, true);
      String originalTarget = buildOriginalTarget(req);
      session.setAttribute(POST_MFA_TARGET, originalTarget);

      if (!res.isCommitted()) {
        res.sendRedirect(ACTIVATE_MFA_PATH);
      }
      return;
    }

    chain.doFilter(req, res);
  }

  private boolean isAllowListed(String path) {
    if (ALLOWLIST_EXACT.contains(path)) {
      return true;
    }
    for (String prefix : ALLOWLIST_PREFIXES) {
      if (path.startsWith(prefix))
        return true;
    }
    return false;
  }

  private boolean isMfaFlowPath(String path) {
    return path.equals(ENABLE_MFA_PATH)
        || path.equals(ACTIVATE_MFA_PATH)
        || path.equals(ACTIVATE_MFA_JSP)
        || path.equals(MFA_API_PATH);
  }

  private String buildOriginalTarget(HttpServletRequest req) {
    String uri = req.getRequestURI();
    String qs = req.getQueryString();
    return (qs == null || qs.isBlank()) ? uri : (uri + "?" + qs);
  }

  private boolean isMfaActive(Optional<IamAccount> authenticatedUserOpt) {
    return authenticatedUserOpt.flatMap(totpMfaRepository::findByAccount)
        .map(IamTotpMfa::isActive)
        .orElse(false);
  }

  @Override
  public void destroy() {
    // Empty method
  }

}
