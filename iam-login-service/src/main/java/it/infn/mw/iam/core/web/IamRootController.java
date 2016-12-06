package it.infn.mw.iam.core.web;

import static it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport.EXT_AUTHN_UNREGISTERED_USER_AUTH;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class IamRootController {

  @RequestMapping({"", "home", "index"})
  public String home(Authentication authentication) {

    if (authentication.getAuthorities().contains(EXT_AUTHN_UNREGISTERED_USER_AUTH)) {
      return "iam/register";
    }
    return "home";
  }

  @PreAuthorize("hasRole('ROLE_USER')")
  @RequestMapping("manage/**")
  public String manage(ModelMap m) {
    return "manage";
  }

}
