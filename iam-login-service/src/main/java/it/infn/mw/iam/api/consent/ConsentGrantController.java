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

package it.infn.mw.iam.api.consent;

import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.exceptions.UnauthorizedUserException;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.account.approved_site.dto.ConsentGrantWithClientDetailsDTO;
import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.core.oauth.consent.ConsentGrantService;
import it.infn.mw.iam.persistence.model.ConsentGrant;
import it.infn.mw.iam.persistence.model.IamAccount;

@SuppressWarnings("deprecation")
@RestController
public class ConsentGrantController {

  public static final String LEGACY_URL = "/api/approved";
  public static final String URL = "/iam/api/approved";
  public static final Logger LOG = LoggerFactory.getLogger(ConsentGrantController.class);

  private final ConsentGrantService service;
  private final AccountUtils accountUtils;

  public ConsentGrantController(ConsentGrantService service, AccountUtils accountUtils) {
    this.service = service;
    this.accountUtils = accountUtils;
  }

  @GetMapping(value = {URL, LEGACY_URL})
  @PreAuthorize("hasRole('ROLE_USER')")
  public List<ConsentGrantWithClientDetailsDTO> getAllConsentGrants() {

    IamAccount account = accountUtils.getAuthenticatedUserAccount()
      .orElseThrow(() -> new IllegalStateException("No IAM account found for authenticated user"));

    return service.getByUserId(account.getUsername()).stream().map(this::toDto).toList();
  }

  @DeleteMapping(value = {URL + "/{id}", LEGACY_URL + "/{id}"})
  @ResponseStatus(value = HttpStatus.NO_CONTENT)
  @PreAuthorize("hasRole('ROLE_USER')")
  public void deleteConsentGrant(@PathVariable Long id, Authentication authn) {

    ConsentGrant approvedSite = findConsentGrant(id);
    validateAuthentication(authn, approvedSite.getUserId());
    service.remove(approvedSite);
  }

  @GetMapping(value = {URL + "/{id}", LEGACY_URL + "/{id}"},
      produces = MediaType.APPLICATION_JSON_VALUE)
  @PreAuthorize("hasRole('ROLE_USER')")
  public ConsentGrantWithClientDetailsDTO getConsentGrant(@PathVariable Long id,
      Authentication authn) {

    ConsentGrant approvedSite = findConsentGrant(id);
    validateAuthentication(authn, approvedSite.getUserId());
    return toDto(approvedSite);
  }

  private ConsentGrant findConsentGrant(Long id) {

    return service.getById(id)
      .orElseThrow(() -> new InvalidRequestException(
          "The requested consent grant with id: " + id + " could not be found."));
  }

  private void validateAuthentication(Authentication authn, String expectedUserId) {

    IamAccount account = accountUtils.getAuthenticatedUserAccount(authn)
      .orElseThrow(() -> new IllegalStateException("No IAM account found for authenticated user"));

    if (!expectedUserId.equals(account.getUsername())) {
      throw new UnauthorizedUserException("You do not have permission to view this consent grant.");
    }
  }

  private ConsentGrantWithClientDetailsDTO toDto(ConsentGrant cg) {

    return new ConsentGrantWithClientDetailsDTO(cg.getId(), cg.getUserId(),
        cg.getClient().getClientId(), cg.getClient().getClientName(),
        cg.getClient().getClientDescription(), cg.getCreationDate(), cg.getAccessDate(),
        cg.getTimeoutDate(), cg.getAllowedScopes());
  }

  @ResponseStatus(value = HttpStatus.NOT_FOUND)
  @ExceptionHandler(InvalidRequestException.class)
  public ErrorDTO handleInvalidRequestException(HttpServletRequest request, Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }

  @ResponseStatus(value = HttpStatus.INTERNAL_SERVER_ERROR)
  @ExceptionHandler(IllegalStateException.class)
  public ErrorDTO handleIllegalStateException(HttpServletRequest request, Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }

  @ResponseStatus(value = HttpStatus.FORBIDDEN)
  @ExceptionHandler(UnauthorizedUserException.class)
  public ErrorDTO handleUnauthorizedUserException(HttpServletRequest request, Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }
}
