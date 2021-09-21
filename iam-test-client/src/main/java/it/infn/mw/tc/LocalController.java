package it.infn.mw.tc;

import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.web.ErrorController;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class LocalController implements ErrorController {

  @Autowired
  IamClientConfig clientConfig;

  @Autowired
  ClientHttpRequestFactory requestFactory;

  @ModelAttribute("iamIssuer")
  public String iamIssuer() {
    return clientConfig.getIssuer();
  }

  @ModelAttribute("scopes")
  public String requestScopes() {
    return clientConfig.getScope().stream().collect(Collectors.joining(" "));
  }

  @ModelAttribute("organizationName")
  public String organizationName() {
    return clientConfig.getOrganizationName();
  }

  @ModelAttribute("hidesTokens")
  public Boolean hidesTokens() {
    return clientConfig.isHideTokens();
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

  @Override
  public String getErrorPath() {

    return "/error";
  }
}
