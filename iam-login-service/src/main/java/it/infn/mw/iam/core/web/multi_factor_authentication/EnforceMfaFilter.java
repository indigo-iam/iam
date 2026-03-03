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

import static it.infn.mw.iam.authn.multi_factor_authentication.MfaVerifyController.MFA_ACTIVATE_URL;
import static it.infn.mw.iam.api.account.multi_factor_authentication.authenticator_app.AuthenticatorAppSettingsController.ADD_SECRET_URL;
import static it.infn.mw.iam.api.account.multi_factor_authentication.authenticator_app.AuthenticatorAppSettingsController.ENABLE_URL;
import static it.infn.mw.iam.api.account.multi_factor_authentication.authenticator_app.AuthenticatorAppSettingsController.REQUESTING_MFA;
import static it.infn.mw.iam.core.web.aup.EnforceAupFilter.AUP_SIGN_PATH;
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
import it.infn.mw.iam.api.account.multi_factor_authentication.IamTotpMfaService;
import it.infn.mw.iam.config.mfa.IamTotpMfaProperties;
import it.infn.mw.iam.persistence.model.IamAccount;

public class EnforceMfaFilter implements Filter {

  public static final Logger LOG = LoggerFactory.getLogger(EnforceMfaFilter.class);

  private static final Set<String> ALLOWLIST_EXACT = Set.of(
      ENABLE_URL,
      ADD_SECRET_URL,
      MFA_ACTIVATE_URL,
      AUP_SIGN_PATH);

  private static final Set<String> ALLOWLIST_PREFIXES = Set.of(
      "/login",
      "/logout",
      "/css/",
      "/js/",
      "/images/",
      "/webjars/");

  private final AccountUtils accountUtils;
  private final IamTotpMfaService iamTotpMfaService;
  private final IamTotpMfaProperties iamTotpMfaProperties;

  public EnforceMfaFilter(AccountUtils accountUtils,
      IamTotpMfaService iamTotpMfaService, IamTotpMfaProperties iamTotpMfaProperties) {
    this.accountUtils = accountUtils;
    this.iamTotpMfaService = iamTotpMfaService;
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
    HttpSession session = req.getSession(false);

    if (LOG.isDebugEnabled()) {
      LOG.debug("[ENFORCE_MFA] Incoming request: method={} path={} session={}",
          req.getMethod(), path, (session != null ? session.getId() : "none"));
    }

    if (isAllowListed(path)) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("[ENFORCE_MFA] Skipping enforcement (allow‑listed): {}", path);
      }
      chain.doFilter(req, res);
      return;
    }

    final boolean mfaMandatory = iamTotpMfaProperties.isMultiFactorMandatory();
    if (!mfaMandatory) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("[ENFORCE_MFA] Skipping enforcement (MFA not mandatory)");
      }
      chain.doFilter(req, res);
      return;
    }

    final boolean authenticated = accountUtils.isAuthenticated();
    if (!authenticated) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("[ENFORCE_MFA] Skipping enforcement (user not authenticated)");
      }
      chain.doFilter(req, res);
      return;
    }

    Optional<IamAccount> authenticatedUserOpt = accountUtils.getAuthenticatedUserAccount();
    if (authenticatedUserOpt.isEmpty()) {
      LOG.warn("[ENFORCE_MFA] Authenticated user cannot be resolved");
      chain.doFilter(req, res);
      return;
    }

    final boolean sessionExists = (session != null);
    if (!sessionExists) {
      LOG.warn("[ENFORCE_MFA] Authenticated user '{}' but no session found", authenticatedUserOpt.get().getUsername());
      chain.doFilter(req, res);
      return;
    }

    final boolean requestingMfa = Boolean.TRUE.equals(session.getAttribute(REQUESTING_MFA));
    if (requestingMfa) {
      if (!res.isCommitted()) {
        LOG.info("[ENFORCE_MFA] User '{}' is already in MFA activation flow -> redirecting to {}",
            authenticatedUserOpt.get().getUsername(), MFA_ACTIVATE_URL);
        res.sendRedirect(MFA_ACTIVATE_URL);
      } else {
        LOG.warn("[ENFORCE_MFA] Wanted to redirect but response already committed");
      }
      return;
    }

    if (!iamTotpMfaService.isAuthenticatorAppActive(authenticatedUserOpt.get())) {
      LOG.info("[ENFORCE_MFA] User '{}' has MFA disabled -> starting MFA activation flow",
          authenticatedUserOpt.get().getUsername());
      session.setAttribute(REQUESTING_MFA, true);

      if (!res.isCommitted()) {
        LOG.info("[ENFORCE_MFA] Redirecting '{}' to {}", authenticatedUserOpt.get().getUsername(), MFA_ACTIVATE_URL);
        res.sendRedirect(MFA_ACTIVATE_URL);
      } else {
        LOG.warn("[ENFORCE_MFA] Unable to redirect to MFA activation page — response already committed");
      }
      return;
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("[ENFORCE_MFA] User '{}' already has MFA active -> continuing request",
          authenticatedUserOpt.get().getUsername());
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

  @Override
  public void destroy() {
    // Empty method
  }

}
