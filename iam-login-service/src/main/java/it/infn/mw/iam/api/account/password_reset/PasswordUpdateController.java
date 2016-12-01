package it.infn.mw.iam.api.account.password_reset;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import it.infn.mw.iam.api.account.password_reset.error.BadUserPasswordError;
import it.infn.mw.iam.api.account.password_reset.error.InvalidPasswordError;
import it.infn.mw.iam.api.account.password_reset.error.UserNotActiveOrNotVerified;
import it.infn.mw.iam.api.scim.controller.utils.ValidationErrorMessageHelper;

@RestController
@RequestMapping(value = PasswordUpdateController.BASE_URL)
@Transactional
public class PasswordUpdateController {

  public final static String BASE_URL = "/iam/password-update";
  public final static String CURRENT_PASSWORD = "currentPassword";
  public final static String UPDATED_PASSWORD = "updatedPassword";

  @Autowired
  private PasswordResetService service;

  @PreAuthorize("hasRole('USER')")
  @RequestMapping(method = RequestMethod.POST)
  @ResponseBody
  public void updatePassword(@ModelAttribute @Valid PasswordDTO password,
      BindingResult validationResults) {

    if (validationResults.hasErrors()) {
      throw new InvalidPasswordError(ValidationErrorMessageHelper
        .buildValidationErrorMessage("Invalid password", validationResults));
    }

    final String username = getUsernameFromSecurityContext();

    service.updatePassword(username, password.getCurrentPassword(), password.getUpdatedPassword());
  }

  private String getUsernameFromSecurityContext() {

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    if (auth instanceof OAuth2Authentication) {
      OAuth2Authentication oauth = (OAuth2Authentication) auth;
      auth = oauth.getUserAuthentication();
    }
    return auth.getName();
  }

  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(BadUserPasswordError.class)
  @ResponseBody
  public String badUserPasswordError(HttpServletRequest req, Exception ex) {
    return ex.getMessage();
  }

  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(InvalidPasswordError.class)
  @ResponseBody
  public String invalidPasswordError(HttpServletRequest req, Exception ex) {
    return ex.getMessage();
  }

  @ResponseStatus(value = HttpStatus.CONFLICT)
  @ExceptionHandler(UserNotActiveOrNotVerified.class)
  @ResponseBody
  public String userNotActiveOrNotVerifiedError(HttpServletRequest req, Exception ex) {
    return ex.getMessage();
  }
}
