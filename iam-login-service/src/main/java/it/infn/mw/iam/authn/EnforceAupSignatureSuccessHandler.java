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

import static it.infn.mw.iam.core.web.aup.EnforceAupFilter.REQUESTING_SIGNATURE;

import java.io.IOException;
import java.util.Date;
import java.util.Optional;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.mitre.openid.connect.web.AuthenticationTimeStamper;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.aup.AUPSignatureCheckService;
import it.infn.mw.iam.core.util.IamAuthenticationLogger;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@SuppressWarnings("deprecation")
public class EnforceAupSignatureSuccessHandler implements AuthenticationSuccessHandler {

  private final AuthenticationSuccessHandler delegate;
  private final AUPSignatureCheckService service;
  private final AccountUtils accountUtils;
  private final IamAccountRepository accountRepo;

  public EnforceAupSignatureSuccessHandler(AuthenticationSuccessHandler delegate,
      AUPSignatureCheckService service, AccountUtils utils, IamAccountRepository accountRepo) {
    this.delegate = delegate;
    this.service = service;
    this.accountUtils = utils;
    this.accountRepo = accountRepo;
  }

  private Optional<Authentication> resolveUserAuthentication(Authentication auth) {
    if (auth instanceof OAuth2Authentication) {
      OAuth2Authentication oauth = (OAuth2Authentication) auth;
      return Optional.ofNullable(oauth.getUserAuthentication());
    }
    return Optional.of(auth);
  }

  private Optional<IamAccount> lookupAuthenticatedUser(Authentication auth) {

    Optional<Authentication> userAuth = resolveUserAuthentication(auth);

    if (userAuth.isPresent()) {
      return accountUtils.getAuthenticatedUserAccount(userAuth.get());
    }

    return Optional.empty();

  }

  protected void setAuthenticationTimestamp(HttpServletRequest request,
      Authentication authentication) {

    Date timestamp = new Date();
    HttpSession session = request.getSession();
    session.setAttribute(AuthenticationTimeStamper.AUTH_TIMESTAMP, timestamp);
    IamAuthenticationLogger.INSTANCE.logAuthenticationSuccess(authentication);
  }

  protected void touchLastLoginTimeForIamAccount(Authentication authentication) {

    resolveUserAuthentication(authentication)
      .ifPresent(a -> accountRepo.touchLastLoginTimeForUserWithUsername(a.getName()));
  }

  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
      Authentication auth) throws IOException, ServletException {

    HttpSession session = request.getSession(false);

    setAuthenticationTimestamp(request, auth);
    touchLastLoginTimeForIamAccount(auth);

    Optional<IamAccount> authenticatedAccount = lookupAuthenticatedUser(auth);

    if (!authenticatedAccount.isPresent()
        || !service.needsAupSignature(authenticatedAccount.get())) {
      delegate.onAuthenticationSuccess(request, response, auth);

    } else {
      session.setAttribute(REQUESTING_SIGNATURE, true);
      response.sendRedirect("/iam/aup/sign");
    }

  }

}
