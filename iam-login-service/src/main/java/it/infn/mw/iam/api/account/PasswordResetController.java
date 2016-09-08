package it.infn.mw.iam.api.account;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import it.infn.mw.iam.api.scim.exception.ScimResourceNotFoundException;

@Controller
public class PasswordResetController {

  @Autowired
  private PasswordResetService service;

  private static final String PLAIN_TEXT = "plain/text";


  @RequestMapping(value = "/iam/password-reset/{token}", method = RequestMethod.GET)
  public String resetPassword(Model model, @PathVariable("token") String token) {
    String message = null;
    try {
      if (!service.checkResetKey(token)) {
        message = "This account is not active or email is not verified. Cannot reset password!";
      }
    } catch (ScimResourceNotFoundException e) {
      message = "Invalid reset key: " + e.getMessage();
    }

    model.addAttribute("errorMessage", message);
    model.addAttribute("resetKey", token);

    return "iam/resetPassword";
  }

  @RequestMapping(value = "/iam/password/reset-key/{token}", method = RequestMethod.GET)
  @ResponseBody
  public Boolean checkResetKey(Model model, @PathVariable("token") String token) {
    return service.checkResetKey(token);
  }


  @RequestMapping(value = "/iam/password-change", method = RequestMethod.POST,
      produces = PLAIN_TEXT)
  @ResponseBody
  public String changePassword(@RequestParam(required = true, name = "resetkey") String resetKey,
      @RequestParam(required = true, name = "password") String password) {
    String retval = null;
    try {
      service.changePassword(resetKey, password);
      retval = "ok";
    } catch (Exception e) {
      retval = "err";
    }
    return retval;
  }


  @RequestMapping(value = "/iam/password-forgot/{email}", method = RequestMethod.GET,
      produces = PLAIN_TEXT)
  @ResponseBody
  public String forgotPassword(@PathVariable("email") String email) {
    service.forgotPassword(email);
    return "ok";
  }

}
