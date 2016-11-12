package it.infn.mw.iam.api.account;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

@Controller
@RequestMapping(PasswordResetController.BASE_RESOURCE)
public class PasswordResetController {

  public static final String BASE_RESOURCE = "/iam/password-reset";
  public static final String BASE_TOKEN_URL = BASE_RESOURCE + "/token";

  @Autowired
  private PasswordResetService service;

  @RequestMapping(value = "/token", method = RequestMethod.POST,
      produces = MediaType.TEXT_PLAIN_VALUE)
  @ResponseBody
  public void createPasswordResetToken(@Valid EmailDTO emailDTO, BindingResult validationResult) {

    if (validationResult.hasErrors()) {
      throw new InvalidEmailAddressError(
          "validation error: " + validationResult.getFieldError("email").getDefaultMessage());
    }

    service.createPasswordResetToken(emailDTO.getEmail());
    return;
  }

  @RequestMapping(value = "/token/{token}", method = RequestMethod.HEAD)
  @ResponseBody
  public String validateResetToken(@PathVariable("token") String token) {
    service.validateResetToken(token);
    return "ok";
  }

  @RequestMapping(value = "/token/{token}", method = RequestMethod.GET)
  public String resetPasswordPage(Model model, @PathVariable("token") String token) {
    String message = null;

    try {

      service.validateResetToken(token);

    } catch (InvalidPasswordResetTokenError e) {
      message = e.getMessage();
    }

    model.addAttribute("statusMessage", message);
    model.addAttribute("resetKey", token);

    return "iam/resetPassword";
  }

  @RequestMapping(value = {"", "/"}, method = RequestMethod.POST)
  @ResponseBody
  public void resetPassword(@RequestParam(required = true, name = "token") String token,
      @RequestParam(required = true, name = "password") String password) {

    service.resetPassword(token, password);
  }

  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(InvalidEmailAddressError.class)
  @ResponseBody
  public String emailValidationError(HttpServletRequest req, Exception ex) {
    return ex.getMessage();
  }

  @ResponseStatus(value = HttpStatus.NOT_FOUND)
  @ExceptionHandler(InvalidPasswordResetTokenError.class)
  @ResponseBody
  public String invalidPasswordRequestTokenError(HttpServletRequest req, Exception ex) {
    return ex.getMessage();
  }

}
