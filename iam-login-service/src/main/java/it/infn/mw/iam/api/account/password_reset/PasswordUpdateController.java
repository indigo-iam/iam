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
import org.springframework.security.access.AccessDeniedException;
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

@SuppressWarnings("deprecation")
@RestController
@Transactional
public class PasswordUpdateController {

  public static final String BASE_URL = "/iam/password-update";
  public static final String CURRENT_PASSWORD = "currentPassword";
  public static final String UPDATED_PASSWORD = "updatedPassword";

  @Autowired
  private PasswordResetService service;

  @PreAuthorize("hasRole('USER')")
  @RequestMapping(method = RequestMethod.POST, path=BASE_URL)
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
  
  @ResponseStatus(value=HttpStatus.FORBIDDEN)
  @ExceptionHandler(AccessDeniedException.class)
  public String accessDeniedError(HttpServletRequest req, Exception ex) {
    return ex.getMessage();
  }
}
