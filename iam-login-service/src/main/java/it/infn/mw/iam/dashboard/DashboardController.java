package it.infn.mw.iam.dashboard;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

@RestController
@RequestMapping(value = "/dashboard")
@Transactional
public class DashboardController {
  
  @PreAuthorize("hasRole('USER')")
  @RequestMapping(method = RequestMethod.GET)
  public ModelAndView showDashboard(HttpServletRequest request) {
    
    return new ModelAndView("iam/dashboard");

  }
}
