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
package it.infn.mw.iam.api.legacy;

import static org.springframework.http.HttpStatus.CREATED;

import java.text.ParseException;

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
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

import it.infn.mw.iam.api.client.registration.service.ClientRegistrationService;
import it.infn.mw.iam.api.common.ClientViews;
import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.core.oauth.scope.SystemScopeService;

@SuppressWarnings("deprecation")
@RestController
@RequestMapping(value = "/resource")
public class LegacyProtectedResourceController {

  private final ClientRegistrationService service;

  public LegacyProtectedResourceController(ClientRegistrationService service) {
    this.service = service;
  }

  @PostMapping
  @ResponseStatus(code = CREATED)
  @JsonView({ClientViews.DynamicRegistration.class})
  public RegisteredClientDTO registerNewProtectedResource(@RequestBody RegisteredClientDTO request,
      Authentication authentication) throws ParseException {

    return service.registerProtectedResource(request, authentication);
  }

  @PreAuthorize("hasRole('ROLE_CLIENT') and #oauth2.hasScope('"
      + SystemScopeService.RESOURCE_TOKEN_SCOPE + "')")
  @GetMapping(value = "/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
  @JsonView({ClientViews.NoSecretDynamicRegistration.class})
  public RegisteredClientDTO readResourceConfiguration(@PathVariable("id") String clientId,
      OAuth2Authentication auth) {

    return service.retrieveClient(clientId, auth);
  }

  @PreAuthorize("hasRole('ROLE_CLIENT') and #oauth2.hasScope('"
      + SystemScopeService.RESOURCE_TOKEN_SCOPE + "')")
  @PutMapping(value = "/{id}", produces = MediaType.APPLICATION_JSON_VALUE,
      consumes = MediaType.APPLICATION_JSON_VALUE)
  @JsonView({ClientViews.NoSecretDynamicRegistration.class})
  public RegisteredClientDTO updateProtectedResource(@PathVariable("id") String clientId,
      @RequestBody RegisteredClientDTO clientDTO, OAuth2Authentication auth) throws ParseException {

    return service.updateProtectedResource(clientId, clientDTO, auth);
  }

  @PreAuthorize("hasRole('ROLE_CLIENT') and #oauth2.hasScope('"
      + SystemScopeService.RESOURCE_TOKEN_SCOPE + "')")
  @DeleteMapping(value = "/{id}")
  public void deleteResource(@PathVariable("id") String clientId,
      OAuth2Authentication auth) {

    service.deleteClient(clientId, auth);
  }

  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(ParseException.class)
  public ErrorDTO badRequestedDtoError(HttpServletRequest req, Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }
}
