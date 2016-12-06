package it.infn.mw.iam.dashboard;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
@RequestMapping(value = "/dashboard")
public class DashboardController {

  @PreAuthorize("hasRole('USER')")
  @RequestMapping(method = RequestMethod.GET)
  public String showDashboard(HttpServletRequest request) {
    return "iam/dashboard";
  }

  @RequestMapping(method = RequestMethod.GET, value = "/expiredsession")
  public String showExpiredSession(HttpServletRequest request) {

    return "iam/expiredsession";

  }
}
