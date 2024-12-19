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
package it.infn.mw.iam.registration;

import static it.infn.mw.iam.api.utils.ValidationErrorUtils.stringifyValidationError;
import static java.lang.String.format;

import java.util.List;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import com.fasterxml.jackson.annotation.JsonView;

import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.api.common.RegistrationViews;
import it.infn.mw.iam.api.scim.exception.ScimResourceNotFoundException;
import it.infn.mw.iam.authn.AbstractExternalAuthenticationToken;
import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.RegistrationProperties;
import it.infn.mw.iam.core.IamRegistrationRequestStatus;
import it.infn.mw.iam.registration.validation.RegistrationRequestValidatorError;

@RestController
@Transactional
@Profile("registration")
public class RegistrationApiController {

  public static final Logger LOG = LoggerFactory.getLogger(RegistrationApiController.class);
  private static final GrantedAuthority USER_AUTHORITY = new SimpleGrantedAuthority("ROLE_USER");

  private final RegistrationRequestService service;
  private final RegistrationProperties registrationProperties;

  private static final String INVALID_REGISTRATION_TEMPLATE = "Invalid registration request: %s";

  public RegistrationApiController(RegistrationRequestService registrationService,
      IamProperties properties) {
    service = registrationService;
    registrationProperties = properties.getRegistration();
  }

  private Optional<ExternalAuthenticationRegistrationInfo> getExternalAuthenticationInfo() {

    Authentication authn = SecurityContextHolder.getContext().getAuthentication();

    if (authn == null) {
      return Optional.empty();
    }

    if (authn instanceof AbstractExternalAuthenticationToken<?>) {

      return Optional.of(((AbstractExternalAuthenticationToken<?>) authn)
        .toExernalAuthenticationRegistrationInfo());
    }

    return Optional.empty();
  }

  @PreAuthorize("#iam.hasScope('registration:read') or hasRole('ADMIN')")
  @GetMapping(value = "/registration/list")
  @ResponseBody
  public List<RegistrationRequestDto> listRequests(
      @RequestParam(value = "status", required = false) IamRegistrationRequestStatus status) {

    return service.listRequests(status);
  }

  @PreAuthorize("#iam.hasScope('registration:read') or hasRole('ADMIN')")
  @GetMapping(value = "/registration/list/pending")
  @ResponseBody
  public List<RegistrationRequestDto> listPendingRequests() {

    return service.listPendingRequests();
  }

  @PostMapping(value = "/registration/create", consumes = "application/json")
  public RegistrationRequestDto createRegistrationRequest(
      @Valid @RequestBody @JsonView(
          value = RegistrationViews.RegistrationDetail.class) RegistrationRequestDto request,
      final BindingResult validationResult) {
    handleValidationError(validationResult);
    return service.createRequest(request, getExternalAuthenticationInfo());
  }

  @PreAuthorize("#iam.hasScope('registration:write') or hasRole('ADMIN')")
  @PostMapping(value = "/registration/approve/{uuid}")
  public RegistrationRequestDto approveRequest(@PathVariable("uuid") String uuid) {
    return service.approveRequest(uuid);
  }

  @PreAuthorize("#iam.hasScope('registration:write') or hasRole('ADMIN')")
  @PostMapping(value = "/registration/reject/{uuid}")
  public RegistrationRequestDto rejectRequest(@PathVariable("uuid") String uuid,
      @RequestParam(required = false) String motivation, @RequestParam(required = false) boolean doNotSendEmail) {

    return service.rejectRequest(uuid, Optional.ofNullable(motivation), doNotSendEmail);
  }

  @GetMapping(value = "/registration/verify/{token}")
  public ModelAndView openConfirmRequestPage(final Model model, @PathVariable("token") String token) {

    model.addAttribute("token", token);
    return new ModelAndView("iam/confirmRequest");
  }

  @PostMapping(value = "/registration/verify")
  public ModelAndView verifyRequest(final Model model, @RequestParam("token") String token) {
    try {
      service.confirmRequest(token);
      model.addAttribute("verificationSuccess", true);
      SecurityContextHolder.clearContext();
    } catch (ScimResourceNotFoundException e) {
      LOG.warn(e.getMessage());
      String message = "Activation failed: " + e.getMessage();
      model.addAttribute("verificationMessage", message);
      model.addAttribute("verificationFailure", true);
    }

    return new ModelAndView("iam/requestVerified");
  }

  @GetMapping(value = "/registration/insufficient-auth")
  public ModelAndView insufficientAuth(final Model model, final HttpServletRequest request,
      final Authentication auth) {

    if (auth.isAuthenticated() && auth.getAuthorities().contains(USER_AUTHORITY)) {
      return new ModelAndView("redirect:/dashboard");
    }

    model.addAttribute("authError", request.getAttribute("authError"));
    return new ModelAndView("iam/insufficient-auth");
  }

  @GetMapping(value = "/registration/submitted")
  public ModelAndView submissionSuccess() {
    SecurityContextHolder.clearContext();
    return new ModelAndView("iam/requestSubmitted");
  }

  @GetMapping(value = "/registration/config")
  public RegistrationProperties registrationConfig() {
    return registrationProperties;
  }

  @ResponseStatus(code = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(RegistrationRequestValidatorError.class)
  public ErrorDTO handleValidationError(RegistrationRequestValidatorError e) {
    return ErrorDTO.fromString(e.getMessage());
  }

  private void handleValidationError(BindingResult result) {
    if (result.hasErrors()) {
      throw new RegistrationRequestValidatorError(
          format(INVALID_REGISTRATION_TEMPLATE, stringifyValidationError(result)));
    }
  }
}
