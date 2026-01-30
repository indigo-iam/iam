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
package it.infn.mw.iam.core.web.aup;

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

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.aup.error.AupNotFoundError;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAup;
import it.infn.mw.iam.persistence.repository.IamAupRepository;
import it.infn.mw.iam.service.aup.AUPSignatureCheckService;


public class EnforceAupFilter implements Filter {

  public static final Logger LOG = LoggerFactory.getLogger(EnforceAupFilter.class);

  public static final String AUP_API_PATH = "/iam/aup";
  public static final String AUP_SIGN_PATH = "/iam/aup/sign";
  public static final String SIGN_AUP_JSP = "signAup.jsp";

  public static final String REQUESTING_SIGNATURE = "iam.aup.requesting-signature";

  final AUPSignatureCheckService signatureCheckService;
  final AccountUtils accountUtils;
  final IamAupRepository aupRepo;


  public EnforceAupFilter(AUPSignatureCheckService signatureCheckService, AccountUtils accountUtils,
      IamAupRepository aupRepo) {
    this.signatureCheckService = signatureCheckService;
    this.accountUtils = accountUtils;
    this.aupRepo = aupRepo;
  }

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    // Empty method
  }


  public boolean sessionOlderThanAupCreation(HttpSession session) {
    IamAup aup = aupRepo.findDefaultAup().orElseThrow(AupNotFoundError::new);
    return session.getCreationTime() < aup.getCreationTime().getTime();
  }


  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {

    HttpServletRequest req = (HttpServletRequest) request;
    HttpServletResponse res = (HttpServletResponse) response;

    HttpSession session = req.getSession(false);

    String requestURL = req.getRequestURL().toString();

    if (LOG.isDebugEnabled()) {
       LOG.debug("[ENFORCE_AUP] Incoming request: method={} path={} session={}",
          req.getMethod(), requestURL, (session != null ? session.getId() : "none"));
    }

    if (!accountUtils.isAuthenticated() || isNull(session) || requestURL.endsWith(AUP_API_PATH)) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("[ENFORCE_AUP] Skip enforcement: authenticated={} sessionPresent={} isAupApi={}",
            accountUtils.isAuthenticated(),
            session != null,
            requestURL.endsWith(AUP_API_PATH));
      }
      chain.doFilter(request, response);
      return;
    }

    Optional<IamAccount> authenticatedUser = accountUtils.getAuthenticatedUserAccount();
    Optional<IamAup> defaultAup = aupRepo.findDefaultAup();

    if (!authenticatedUser.isPresent() || !defaultAup.isPresent()) {
      LOG.warn("[ENFORCE_AUP] Skip enforcement due to missing prerequisites: userPresent={} defaultAupPresent={}",
          authenticatedUser.isPresent(),
          defaultAup.isPresent());
      chain.doFilter(request, response);
      return;
    }

    if (!isNull(session.getAttribute(REQUESTING_SIGNATURE))) {
      if (requestURL.endsWith(AUP_SIGN_PATH) || requestURL.endsWith(SIGN_AUP_JSP)) {
        if (LOG.isDebugEnabled()) {
          LOG.debug("[ENFORCE_AUP] Signature flow active; allowing sign page");
        }
        chain.doFilter(request, response);
        return;
      }
      if (res.isCommitted()) {
        LOG.warn("[ENFORCE_AUP] Wanted to redirect to AUP_SIGN_PATH but response already committed");
        return;
      }

      LOG.info("[ENFORCE_AUP] Redirecting to AUP sign page (signature flow active): from={}", req.getRequestURI());
      res.sendRedirect(AUP_SIGN_PATH);
      return;
    }

    boolean needsSignature = signatureCheckService.needsAupSignature(authenticatedUser.get());
    boolean sessionOk = !sessionOlderThanAupCreation(session);
    boolean committed = res.isCommitted();

    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "[ENFORCE_AUP] Enforcement evaluation: needsSignature={} sessionOlderThanAupCreation={} responseCommitted={} {}",
          needsSignature,
          !sessionOk,
          committed);
    }

    if (needsSignature && sessionOk && !committed) {
      LOG.info("[ENFORCE_AUP] Redirecting to AUP sign page (needs signature): from={}", req.getRequestURI());
      session.setAttribute(REQUESTING_SIGNATURE, true);
      res.sendRedirect(AUP_SIGN_PATH);
      return;
    }

    if (LOG.isDebugEnabled()) {
      LOG.debug("[ENFORCE_AUP] Continue filter chain");
    }

    chain.doFilter(request, response);
  }

  @Override
  public void destroy() {
    // Empty method
  }
}
