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

import java.util.List;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
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
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.api.scim.exception.ScimResourceNotFoundException;
import it.infn.mw.iam.authn.AbstractExternalAuthenticationToken;
import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.RegistrationProperties;
import it.infn.mw.iam.core.IamRegistrationRequestStatus;
import it.infn.mw.iam.registration.validation.RegistrationRequestValidatorError;
import static it.infn.mw.iam.api.utils.ValidationErrorUtils.stringifyValidationError;
import static java.lang.String.format;

@RestController
@Transactional
@Profile("registration")
public class RegistrationApiController {

  public static final Logger LOG = LoggerFactory.getLogger(RegistrationApiController.class);
  private static final GrantedAuthority USER_AUTHORITY = new SimpleGrantedAuthority("ROLE_USER");

  private final RegistrationRequestService service;
  private final RegistrationProperties registrationProperties;

  private static final String INVALID_REGISTRATION_TEMPLATE = "Invalid registration request: %s";

  @Autowired
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



  @PreAuthorize("#oauth2.hasScope('registration:read') or hasRole('ADMIN')")
  @RequestMapping(value = "/registration/list", method = RequestMethod.GET)
  @ResponseBody
  public List<RegistrationRequestDto> listRequests(
      @RequestParam(value = "status", required = false) IamRegistrationRequestStatus status) {

    return service.listRequests(status);
  }

  @PreAuthorize("#oauth2.hasScope('registration:read') or hasRole('ADMIN')")
  @RequestMapping(value = "/registration/list/pending", method = RequestMethod.GET)
  @ResponseBody
  public List<RegistrationRequestDto> listPendingRequests() {

    return service.listPendingRequests();
  }

  @RequestMapping(value = "/registration/create", method = RequestMethod.POST,
      consumes = "application/json")
  public RegistrationRequestDto createRegistrationRequest(
      @RequestBody @Validated RegistrationRequestDto request, final BindingResult validationResult) {
    handleValidationError(validationResult);
    return service.createRequest(request, getExternalAuthenticationInfo());

  }

  @PreAuthorize("#oauth2.hasScope('registration:write') or hasRole('ADMIN')")
  @RequestMapping(value = "/registration/approve/{uuid}", method = RequestMethod.POST)
  public RegistrationRequestDto approveRequest(@PathVariable("uuid") String uuid) {
    return service.approveRequest(uuid);
  }

  @PreAuthorize("#oauth2.hasScope('registration:write') or hasRole('ADMIN')")
  @RequestMapping(value = "/registration/reject/{uuid}", method = RequestMethod.POST)
  public RegistrationRequestDto rejectRequest(@PathVariable("uuid") String uuid,
      @RequestParam(required = false) String motivation) {

    return service.rejectRequest(uuid, Optional.ofNullable(motivation));
  }


  @RequestMapping(value = "/registration/confirm/{token}", method = RequestMethod.GET)
  public RegistrationRequestDto confirmRequest(@PathVariable("token") String token) {

    return service.confirmRequest(token);
  }

  @RequestMapping(value = "/registration/verify/{token}", method = RequestMethod.GET)
  public ModelAndView verify(final Model model, @PathVariable("token") String token) {
    try {
      service.confirmRequest(token);
      model.addAttribute("verificationSuccess", true);
      SecurityContextHolder.clearContext();
    } catch (ScimResourceNotFoundException e) {
      LOG.warn(e.getMessage(), e);
      String message = "Activation failed: " + e.getMessage();
      model.addAttribute("verificationMessage", message);
      model.addAttribute("verificationFailure", true);
    }

    return new ModelAndView("iam/requestVerified");
  }

  @RequestMapping(value = "/registration/insufficient-auth", method = RequestMethod.GET)
  public ModelAndView insufficientAuth(final Model model, final HttpServletRequest request, final Authentication auth) {
    
    if (auth.isAuthenticated() && auth.getAuthorities().contains(USER_AUTHORITY)) {
      return new ModelAndView("redirect:/dashboard");
    }
    
    model.addAttribute("authError", request.getAttribute("authError"));
    return new ModelAndView("iam/insufficient-auth");
  }

  @RequestMapping(value = "/registration/submitted", method = RequestMethod.GET)
  public ModelAndView submissionSuccess() {
    SecurityContextHolder.clearContext();
    return new ModelAndView("iam/requestSubmitted");
  }

  @RequestMapping(value = "/registration/config", method = RequestMethod.GET)
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
