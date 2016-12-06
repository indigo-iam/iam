package it.infn.mw.iam.registration;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import it.infn.mw.iam.api.scim.exception.IllegalArgumentException;
import it.infn.mw.iam.api.scim.exception.ScimResourceNotFoundException;
import it.infn.mw.iam.authn.AbstractExternalAuthenticationToken;
import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo;
import it.infn.mw.iam.core.IamRegistrationRequestStatus;

@RestController
@Transactional
@Profile("registration")
public class RegistrationController {

  private RegistrationRequestService service;

  private Optional<ExternalAuthenticationRegistrationInfo> getExternalAuthenticationInfo() {

    Authentication authn = SecurityContextHolder.getContext().getAuthentication();

    if (authn == null) {
      return Optional.empty();
    }

    if (authn instanceof AbstractExternalAuthenticationToken<?>) {

      return Optional
        .of(((AbstractExternalAuthenticationToken<?>) authn).toExernalAuthenticationInfo());
    }

    return Optional.empty();
  }

  @Autowired
  public RegistrationController(RegistrationRequestService registrationService) {
    service = registrationService;
  }

  @RequestMapping(value = "/registration/username-available/{username:.+}",
      method = RequestMethod.GET)
  public Boolean usernameAvailable(@PathVariable("username") String username) {
    return service.usernameAvailable(username);
  }

  @RequestMapping(value = "/registration/email-available/{email:.+}", method = RequestMethod.GET)
  public Boolean emailAvailable(@PathVariable("email") String email) {
    Boolean emailAvaiable = service.emailAvailable(email);
    return emailAvaiable;
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
      @RequestBody RegistrationRequestDto request) {

    return service.createRequest(request, getExternalAuthenticationInfo());

  }

  @PreAuthorize("#oauth2.hasScope('registration:write') or hasRole('ADMIN')")
  @RequestMapping(value = "/registration/{uuid}/{decision}", method = RequestMethod.POST)
  public RegistrationRequestDto changeStatus(@PathVariable("uuid") String uuid,
      @PathVariable("decision") String decision) {

    IamRegistrationRequestStatus status = null;
    try {
      status = IamRegistrationRequestStatus.valueOf(decision);
    } catch (Exception e) {
      throw new IllegalArgumentException(String.format("Operation [%s] not found", decision));
    }

    return service.updateStatus(uuid, status);
  }

  @RequestMapping(value = "/registration/confirm/{token}", method = RequestMethod.GET)
  public RegistrationRequestDto confirmEmail(@PathVariable("token") String token) {

    return service.confirmRequest(token);
  }

  @RequestMapping(value = "/registration/verify/{token}", method = RequestMethod.GET)
  public ModelAndView verify(final Model model, @PathVariable("token") String token) {
    try {
      service.confirmRequest(token);
      model.addAttribute("verificationSuccess", true);
      SecurityContextHolder.clearContext();
    } catch (ScimResourceNotFoundException e) {
      String message = "Activation failed: " + e.getMessage();
      model.addAttribute("verificationMessage", message);
      model.addAttribute("verificationFailure", true);
    }

    return new ModelAndView("iam/requestVerified");
  }

  @RequestMapping(value = "/registration/submitted", method = RequestMethod.GET)
  public ModelAndView submissionSuccess() {
    SecurityContextHolder.clearContext();
    return new ModelAndView("iam/requestSubmitted");
  }

}
