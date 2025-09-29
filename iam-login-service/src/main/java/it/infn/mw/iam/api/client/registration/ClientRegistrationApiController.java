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
package it.infn.mw.iam.api.client.registration;

import static org.springframework.http.HttpStatus.CREATED;
import static org.springframework.http.HttpStatus.NO_CONTENT;

import java.text.ParseException;

import javax.servlet.http.HttpServletRequest;
import javax.validation.ConstraintViolationException;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.annotation.JsonView;

import it.infn.mw.iam.api.client.error.ClientSuspended;
import it.infn.mw.iam.api.client.error.InvalidClientRegistrationRequest;
import it.infn.mw.iam.api.client.error.NoSuchClient;
import it.infn.mw.iam.api.client.registration.service.ClientRegistrationService;
import it.infn.mw.iam.api.common.ClientViews;
import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;

@RestController
@RequestMapping(
    value = {ClientRegistrationApiController.ENDPOINT})
public class ClientRegistrationApiController {

  public static final String ENDPOINT = "/iam/api/client-registration";

  private final ClientRegistrationService service;

  public ClientRegistrationApiController(ClientRegistrationService service) {
    this.service = service;
  }

  @PostMapping
  @ResponseStatus(code = CREATED)
  @JsonView({ClientViews.DynamicRegistration.class})
  public RegisteredClientDTO registerClient(@RequestBody RegisteredClientDTO request,
      Authentication authentication) throws ParseException {
    return service.registerClient(request, authentication);

  }

  @JsonView({ClientViews.DynamicRegistration.class})
  @GetMapping("/{clientId}")
  public RegisteredClientDTO retrieveClient(@PathVariable String clientId,
      Authentication authentication) {

    return service.retrieveClient(clientId, authentication);
  }

  @PutMapping("/{clientId}")
  @JsonView({ClientViews.DynamicRegistration.class})
  public RegisteredClientDTO updateClient(@PathVariable String clientId,
      @RequestBody RegisteredClientDTO request, Authentication authentication)
      throws ParseException {

    return service.updateClient(clientId, request, authentication);
  }

  @DeleteMapping("/{clientId}")
  @ResponseStatus(code = NO_CONTENT)
  public void deleteClient(@PathVariable String clientId, Authentication authentication) {
    service.deleteClient(clientId, authentication);
  }


  @PostMapping("/{clientId}/redeem")
  @JsonView({ClientViews.DynamicRegistration.class})
  public RegisteredClientDTO redeemClient(@PathVariable String clientId,
      @RequestBody String registrationAccessToken, Authentication authentication) {
    return service.redeemClient(clientId, registrationAccessToken, authentication);
  }

  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(ConstraintViolationException.class)
  public ErrorDTO constraintValidationError(HttpServletRequest req, Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }

  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(ParseException.class)
  public ErrorDTO parseExceptionError(HttpServletRequest req, Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }

  @ResponseStatus(value = HttpStatus.NOT_FOUND)
  @ExceptionHandler(NoSuchClient.class)
  public ErrorDTO noSuchClient(HttpServletRequest req, Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }

  @ResponseStatus(value = HttpStatus.FORBIDDEN)
  @ExceptionHandler(ClientSuspended.class)
  public ErrorDTO clientSuspended(HttpServletRequest req, Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }

  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(InvalidClientRegistrationRequest.class)
  public ErrorDTO invalidRequest(HttpServletRequest req, Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }

  @ResponseStatus(value = HttpStatus.FORBIDDEN)
  @ExceptionHandler(AccessDeniedException.class)
  public ErrorDTO authorizationError(HttpServletRequest req, Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }
}
