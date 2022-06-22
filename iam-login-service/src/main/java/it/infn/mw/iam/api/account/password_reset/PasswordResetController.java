/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2021
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package it.infn.mw.iam.api.account.password_reset;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

import it.infn.mw.iam.api.account.password_reset.error.InvalidEmailAddressError;
import it.infn.mw.iam.api.account.password_reset.error.InvalidPasswordResetTokenError;

@Controller
@RequestMapping(PasswordResetController.BASE_RESOURCE)
public class PasswordResetController {

  public static final String BASE_RESOURCE = "/iam/password-reset";
  public static final String BASE_TOKEN_URL = BASE_RESOURCE + "/token";

  private static final String EMAIL_FIELD = "email";
  private static final String EMAIL_VALIDATION_ERROR_MSG = "invalid email address";

  @Autowired
  private PasswordResetService service;

  private String nullSafeValidationErrorMessage(BindingResult validationResult) {
    
    FieldError result = validationResult.getFieldError(EMAIL_FIELD);
    if (result == null) {
      return EMAIL_VALIDATION_ERROR_MSG;
    } else {
      return result.getDefaultMessage();
    }
  }


  @RequestMapping(value = "/token", method = RequestMethod.POST,
      produces = MediaType.TEXT_PLAIN_VALUE)
  @ResponseBody
  public void createPasswordResetToken(@Valid EmailDTO emailDTO, BindingResult validationResult) {

    if (validationResult.hasErrors()) {
      throw new InvalidEmailAddressError(
          String.format("validation error: %s", nullSafeValidationErrorMessage(validationResult)));
    }

    service.createPasswordResetToken(emailDTO.getEmail());

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
