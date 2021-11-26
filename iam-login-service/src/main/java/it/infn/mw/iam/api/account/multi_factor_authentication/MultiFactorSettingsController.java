package it.infn.mw.iam.api.account.multi_factor_authentication;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import it.infn.mw.iam.api.common.NoSuchAccountError;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@SuppressWarnings("deprecation")
@Controller
@RequestMapping("iam/multi-factor-settings")
public class MultiFactorSettingsController {

  final IamAccountRepository accountRepository;

  @Autowired
  public MultiFactorSettingsController(IamAccountRepository accountRepository) {
    this.accountRepository = accountRepository;
  }

  @PreAuthorize("hasRole('USER')")
  @RequestMapping(value = "/get-settings", method = RequestMethod.GET,
      produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  public MultiFactorSettingsDTO getMultiFactorSettings() {

    final String username = getUsernameFromSecurityContext();
    IamAccount account = accountRepository.findByUsername(username)
      .orElseThrow(() -> NoSuchAccountError.forUsername(username));

    MultiFactorSettingsDTO dto = new MultiFactorSettingsDTO();
    dto.setAuthenticatorAppActive(account.getTotpMfa() != null && account.getTotpMfa().isActive());
    // add further factors if/when implemented

    return dto;
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
