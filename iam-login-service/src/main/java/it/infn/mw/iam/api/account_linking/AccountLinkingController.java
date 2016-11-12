package it.infn.mw.iam.api.account_linking;


import java.io.IOException;
import java.security.Principal;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import it.infn.mw.iam.authn.AbstractExternalAuthenticationToken;
import it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport;
import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo.ExternalAuthenticationType;
import it.infn.mw.iam.authn.error.AccountAlreadyLinkedError;

@Controller
@RequestMapping(AccountLinkingController.ACCCOUNT_LINKING_BASE_RESOURCE)
public class AccountLinkingController extends ExternalAuthenticationHandlerSupport {
  final AccountLinkingService linkingService;

  @Autowired
  public AccountLinkingController(AccountLinkingService s) {
    linkingService = s;
  }

  @PreAuthorize("hasRole('USER')")
  @RequestMapping(value = "/{type}", method = RequestMethod.GET)
  public void linkAccount(@PathVariable ExternalAuthenticationType type, Authentication authn,
      HttpServletRequest request, HttpServletResponse response) throws IOException {

    HttpSession session = request.getSession();

    clearAccountLinkingSessionAttributes(session);
    setupAccountLinkingSessionKey(session, type);
    saveAuthenticationInSession(session, authn);

    response.sendRedirect(mapExternalAuthenticationTypeToExternalAuthnURL(type));
  }

  @PreAuthorize("hasRole('USER')")
  @RequestMapping(value = "/{type}/done", method = RequestMethod.GET)
  public String finalizeAccountLinking(@PathVariable ExternalAuthenticationType type,
      Principal principal, HttpServletRequest request, HttpServletResponse response)
	  throws IOException {

    HttpSession session = request.getSession();

    AbstractExternalAuthenticationToken<?> externalAuthenticationToken =
	getExternalAuthenticationTokenFromSession(session).orElseThrow(() -> {
	  clearAccountLinkingSessionAttributes(session);
	  return new IllegalArgumentException("No external authentication token found in session");
	});

    linkingService.linkExternalAccount(principal, externalAuthenticationToken);
    clearAccountLinkingSessionAttributes(session);

    return "redirect:/dashboard";

  }


  @ExceptionHandler(AccountAlreadyLinkedError.class)
  public String accountAlreadyLinkedError(HttpServletRequest request, Exception ex) {
    clearAccountLinkingSessionAttributes(request.getSession());
    saveAccountLinkingError(request.getSession(), ex);
    return "redirect:/dashboard";
  }

}
