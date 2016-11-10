package it.infn.mw.iam.dashboard;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import it.infn.mw.iam.core.web.LoginPageConfiguration;

@RestController
@RequestMapping(value = "/dashboard")
@Transactional
public class DashboardController {

  @Autowired
  LoginPageConfiguration loginPageConfiguration;

  @PreAuthorize("hasRole('USER')")
  @RequestMapping(method = RequestMethod.GET)
  public ModelAndView showDashboard(HttpServletRequest request) {

    ModelAndView dashboard = new ModelAndView("iam/dashboard");
    dashboard.getModelMap().addAttribute("isRegistrationEnabled",
        loginPageConfiguration.isRegistrationEnabled());
    return dashboard;
  }

  @RequestMapping(method = RequestMethod.GET, value = "/expiredsession")
  public ModelAndView showExpiredSession(HttpServletRequest request) {

    return new ModelAndView("iam/expiredsession");

  }
}
