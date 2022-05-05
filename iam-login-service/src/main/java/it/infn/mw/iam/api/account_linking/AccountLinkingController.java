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
package it.infn.mw.iam.api.account_linking;


import static java.lang.String.format;

import java.io.IOException;
import java.security.Principal;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import it.infn.mw.iam.authn.AbstractExternalAuthenticationToken;
import it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport;
import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo.ExternalAuthenticationType;
import it.infn.mw.iam.authn.x509.IamX509AuthenticationCredential;

@Controller
@CrossOrigin(origins = "*")
@RequestMapping(AccountLinkingController.ACCOUNT_LINKING_BASE_RESOURCE)
public class AccountLinkingController extends ExternalAuthenticationHandlerSupport {
  final AccountLinkingService linkingService;

  @Value("${iam.account-linking.enable}")
  private Boolean accountLinkingEnabled;

  @Autowired
  public AccountLinkingController(AccountLinkingService s) {
    linkingService = s;
  }


  @PreAuthorize("hasRole('USER')")
  @RequestMapping(value = "/X509", method = RequestMethod.DELETE)
  @ResponseStatus(value = HttpStatus.NO_CONTENT)
  public void unlinkX509Certificate(Principal principal, @RequestParam String certificateSubject,
      RedirectAttributes attributes) {

    checkAccountLinkingEnabled(attributes);
    linkingService.unlinkX509Certificate(principal, certificateSubject);
  }


  @PreAuthorize("hasRole('USER')")
  @RequestMapping(value = "/X509", method = RequestMethod.POST)
  public String linkX509Certificate(HttpSession session, Principal principal,
      RedirectAttributes attributes) {

    clearAccountLinkingSessionAttributes(session);
    checkAccountLinkingEnabled(attributes);

    try {
      IamX509AuthenticationCredential cred = getSavedX509AuthenticationCredential(session)
        .orElseThrow(() -> new IllegalArgumentException(
            format("No X.509 credential found in session for user '%s'", principal.getName())));

      linkingService.linkX509Certificate(principal, cred);
      saveX509LinkingSuccess(cred, attributes);

    } catch (Exception ex) {
      saveAccountLinkingError(ex, attributes);
    }

    return "redirect:/dashboard";
  }


  private void checkAccountLinkingEnabled(RedirectAttributes attributes) {
    if (!accountLinkingEnabled) {
      AccountLinkingDisabledException ex = new AccountLinkingDisabledException();
      saveAccountLinkingError(ex, attributes);
      throw ex;
    }
  }

  @PreAuthorize("hasRole('USER')")
  @RequestMapping(value = "/{type}", method = RequestMethod.POST)
  public void linkAccount(@PathVariable ExternalAuthenticationType type,
      @RequestParam(value = "id", required = false) String externalIdpId, Authentication authn,
      final RedirectAttributes redirectAttributes, HttpServletRequest request,
      HttpServletResponse response) throws IOException {

    checkAccountLinkingEnabled(redirectAttributes);

    HttpSession session = request.getSession();

    clearAccountLinkingSessionAttributes(session);
    setupAccountLinkingSessionKey(session, type);
    saveAuthenticationInSession(session, authn);

    response.sendRedirect(mapExternalAuthenticationTypeToExternalAuthnURL(type, externalIdpId));
  }

  @PreAuthorize("hasRole('USER')")
  @RequestMapping(value = "/{type}/done", method = {RequestMethod.GET, RequestMethod.POST})
  public String finalizeAccountLinking(@PathVariable ExternalAuthenticationType type,
      Principal principal, final RedirectAttributes redirectAttributes, HttpServletRequest request,
      HttpServletResponse response) {

    checkAccountLinkingEnabled(redirectAttributes);
    HttpSession session = request.getSession();
    principal = getAccountLinkingSavedAuthentication(session);

    if (principal == null) {
      principal = getAccountLinkingSavedAuthentication(session);
    }

    if (!hasAccountLinkingDoneKey(session)) {
      throw new IllegalArgumentException("No account linking done key found in request.");
    }

    AbstractExternalAuthenticationToken<?> externalAuthenticationToken =
        getExternalAuthenticationTokenFromSession(session).orElseThrow(() -> {
          clearAccountLinkingSessionAttributes(session);

          return new IllegalArgumentException("No external authentication token found in session");
        });

    try {

      linkingService.linkExternalAccount(principal, externalAuthenticationToken);
      saveAccountLinkingSuccess(externalAuthenticationToken, redirectAttributes);

    } catch (Exception ex) {

      saveAccountLinkingError(ex, redirectAttributes);

    } finally {
      clearAccountLinkingSessionAttributes(session);
    }

    return "redirect:/dashboard";

  }

  @PreAuthorize("hasRole('USER')")
  @RequestMapping(value = "/{type}", method = RequestMethod.DELETE)
  @ResponseStatus(value = HttpStatus.NO_CONTENT)
  public void unlinkAccount(@PathVariable ExternalAuthenticationType type, Principal principal,
      @RequestParam("iss") String issuer, @RequestParam("sub") String subject,
      @RequestParam(name = "attr", required = false) String attributeId,
      final RedirectAttributes redirectAttributes) {

    checkAccountLinkingEnabled(redirectAttributes);
    linkingService.unlinkExternalAccount(principal, type, issuer, subject, attributeId);
  }

  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(IllegalArgumentException.class)
  public String handleIllegalArgumentException(HttpServletRequest request, Exception ex) {
    return "iam/dashboard";
  }

  @ResponseStatus(value = HttpStatus.FORBIDDEN)
  @ExceptionHandler(AccountLinkingDisabledException.class)
  public String handleAccountLinkingDisabledException(HttpServletRequest request, Exception ex) {
    return "iam/dashboard";
  }
}
