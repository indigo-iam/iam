package it.infn.mw.iam.api.account.multi_factor_authentication.authenticator_app;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import it.infn.mw.iam.api.common.NoSuchAccountError;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

import org.springframework.stereotype.Controller;

@SuppressWarnings("deprecation")
@Controller
@RequestMapping("/iam/authenticator-app")
public class AuthenticatorAppController {

  final IamAccountService service;
  final IamAccountRepository accountRepository;

  @Autowired
  public AuthenticatorAppController(IamAccountService service,
      IamAccountRepository accountRepository) {
    this.service = service;
    this.accountRepository = accountRepository;
  }

  // TODO switch to this post method from get request, post method not currently working
  @PreAuthorize("hasRole('USER')")
  @RequestMapping(value = "/enable", method = RequestMethod.POST,
      produces = MediaType.TEXT_PLAIN_VALUE)
  @ResponseBody
  public void enableAuthenticatorApp(@Valid CodeDTO code) {
    final String username = getUsernameFromSecurityContext();
    IamAccount account = accountRepository.findByUsername(username)
      .orElseThrow(() -> NoSuchAccountError.forUsername(username));

    service.addTotpMfaSecret(account);

    // TODO checks to see if provided code valid
  }

  @PreAuthorize("hasRole('USER')")
  @RequestMapping(value = "/enabled", method = RequestMethod.GET,
      produces = MediaType.TEXT_PLAIN_VALUE)
  @ResponseBody
  public void getenableAuthenticatorApp() {
    final String username = getUsernameFromSecurityContext();
    IamAccount account = accountRepository.findByUsername(username)
      .orElseThrow(() -> NoSuchAccountError.forUsername(username));

    service.addTotpMfaSecret(account);

    // TODO checks to see if provided code valid
  }

  @PreAuthorize("hasRole('USER')")
  @RequestMapping(method = RequestMethod.POST, value = "/disable",
      produces = MediaType.TEXT_PLAIN_VALUE)
  @ResponseBody
  public void disableAuthenticatorApp(@ModelAttribute @Valid CodeDTO code) {
    final String username = getUsernameFromSecurityContext();
    IamAccount account = accountRepository.findByUsername(username)
      .orElseThrow(() -> NoSuchAccountError.forUsername(username));

    // TODO checks to see if provided code valid

    service.removeTotpMfaSecret(account);
  }

  private String getUsernameFromSecurityContext() {

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    if (auth instanceof OAuth2Authentication) {
      OAuth2Authentication oauth = (OAuth2Authentication) auth;
      auth = oauth.getUserAuthentication();
    }
    return auth.getName();
  }
}
