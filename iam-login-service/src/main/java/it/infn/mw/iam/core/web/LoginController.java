package it.infn.mw.iam.core.web;

import java.security.Principal;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import it.infn.mw.iam.core.IamProperties;

@Controller
public class LoginController {

  public static final String LOGIN_PAGE_CONFIGURATION_KEY = "loginPageConfiguration";
  public static final String IAM_PROPERTIES__KEY = "iamProperties";

  @Autowired
  LoginPageConfiguration loginPageConfiguration;

  @Autowired
  IamProperties properties;

  @RequestMapping("/login")
  public String login(Principal principal, Model model, HttpServletRequest request) {

    if (principal == null || principal instanceof AnonymousAuthenticationToken) {

      model.addAttribute(LOGIN_PAGE_CONFIGURATION_KEY, loginPageConfiguration);
      model.addAttribute(IAM_PROPERTIES__KEY, properties);

      return "iam/login";
    }

    return "redirect:/";

  }

}
