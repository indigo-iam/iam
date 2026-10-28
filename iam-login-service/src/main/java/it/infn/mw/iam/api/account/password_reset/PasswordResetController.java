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

import javax.validation.Valid;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.util.HtmlUtils;

import it.infn.mw.iam.api.account.password_reset.error.InvalidEmailAddressError;
import it.infn.mw.iam.api.account.password_reset.error.InvalidPasswordError;
import it.infn.mw.iam.api.account.password_reset.error.InvalidPasswordResetTokenError;
import it.infn.mw.iam.api.scim.controller.utils.ValidationErrorMessageHelper;

@Controller
public class PasswordResetController {

  public static final String BASE_RESOURCE = "/iam/password-reset";
  public static final String BASE_TOKEN_URL = BASE_RESOURCE + "/token";

  private static final String EMAIL_FIELD = "email";
  private static final String EMAIL_VALIDATION_ERROR_MSG = "invalid email address";

  private final PasswordResetService service;

  public PasswordResetController(PasswordResetService service) {
    this.service = service;
  }

  private String nullSafeValidationErrorMessage(BindingResult validationResult) {
    FieldError error = validationResult.getFieldError(EMAIL_FIELD);

    return error != null && error.getDefaultMessage() != null ? error.getDefaultMessage()
        : EMAIL_VALIDATION_ERROR_MSG;
  }

  @PostMapping(value = BASE_TOKEN_URL, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  @ResponseBody
  public void createPasswordResetToken(@Valid EmailDTO emailDTO, BindingResult validationResult) {

    if (validationResult.hasErrors()) {
      throw new InvalidEmailAddressError(
          String.format("validation error: %s", nullSafeValidationErrorMessage(validationResult)));
    }

    service.createPasswordResetToken(emailDTO.getEmail());
  }

  @RequestMapping(value = BASE_TOKEN_URL + "/{token}", method = RequestMethod.HEAD)
  @ResponseBody
  public void validateResetToken(@PathVariable String token) {
    service.validateResetToken(sanitizeToken(token));
  }

  @GetMapping(value = BASE_TOKEN_URL + "/{token}")
  public String resetPasswordPage(Model model, @PathVariable String token) {

    String sanitizedToken = sanitizeToken(token);
    try {
      service.validateResetToken(sanitizedToken);
      model.addAttribute("resetKey", sanitizedToken);
    } catch (InvalidPasswordResetTokenError e) {
      model.addAttribute("errorMessage", e.getMessage());
    }
    return "iam/resetPassword";
  }

  @PostMapping(value = {"/iam/password-reset", "/iam/password-reset/"},
      consumes = MediaType.APPLICATION_JSON_VALUE)
  @ResponseStatus(HttpStatus.CREATED)
  @ResponseBody
  public void resetPassword(@RequestBody @Valid ResetPasswordDTO password,
      BindingResult validationResult) {

    if (validationResult.hasErrors()) {
      throw new InvalidPasswordError(ValidationErrorMessageHelper
        .buildValidationErrorMessage("Invalid reset password", validationResult));
    }
    service.resetPassword(password.getToken(), password.getUpdatedPassword());
  }

  @ResponseStatus(HttpStatus.BAD_REQUEST)
  @ExceptionHandler({InvalidEmailAddressError.class, InvalidPasswordError.class})
  @ResponseBody
  public String validationError(Exception ex) {
    return ex.getMessage();
  }

  @ResponseStatus(HttpStatus.NOT_FOUND)
  @ExceptionHandler(InvalidPasswordResetTokenError.class)
  @ResponseBody
  public String invalidPasswordRequestTokenError(InvalidPasswordResetTokenError ex) {
    return ex.getMessage();
  }

  private String sanitizeToken(String token) {
    return HtmlUtils.htmlEscape(token);
  }
}
