package it.infn.mw.tc;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class LocalController implements ErrorController {

  @Autowired
  IamClientApplicationProperties properties;

  @Autowired
  ClientHttpRequestFactory requestFactory;

  @ModelAttribute("iamIssuer")
  public String iamIssuer() {
    return properties.getIssuer();
  }

  @ModelAttribute("scopes")
  public String requestScopes() {
    return properties.getClient().getScope();
  }

  @ModelAttribute("organizationName")
  public String organizationName() {
    return properties.getOrganizationName();
  }

  @ModelAttribute("hidesTokens")
  public Boolean hidesTokens() {
    return properties.isHideTokens();
  }

  @RequestMapping("/")
  public String index(Model model) {
    return "index";
  }

  @RequestMapping("/error")
  public String error(HttpServletRequest request, Model model) {

    AuthenticationException authException = (AuthenticationException) request.getAttribute("authnException");

    if (authException == null) {
      model.addAttribute("error", "Unexpected error");
    } else {
      model.addAttribute("error", authException.getMessage());
    }

    return "index";
  }
}
