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

import javax.persistence.EntityNotFoundException;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.core.oauth.consent.ConsentExemptionService;
import it.infn.mw.iam.persistence.model.ConsentExemption;

@RestController
@RequestMapping("/api/whitelist")
public class ConsentExemptionController {

  private final ConsentExemptionService exemptionService;

  public ConsentExemptionController(ConsentExemptionService exceptionService) {
    this.exemptionService = exceptionService;
  }

  @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
  @PreAuthorize("#iam.hasScope('iam:admin.read') or #iam.hasDashboardRole('ROLE_ADMIN')")
  public List<ConsentExemptionDTO> getAllConsentExemptions() {

    return exemptionService.findAll().stream().map(ConsentExemptionDTO::from).toList();
  }

  @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE,
      produces = MediaType.APPLICATION_JSON_VALUE)
  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN')")
  public ConsentExemptionDTO addNewConsentExemption(@RequestBody ConsentExemptionDTO dto, Authentication auth) {

    ConsentExemption whitelist = new ConsentExemption();
    whitelist.setClientId(dto.clientId());
    whitelist.setCreatorUserId(auth.getName());
    whitelist.setAllowedScopes(dto.allowedScopes());
    return ConsentExemptionDTO.from(exemptionService.save(whitelist));
  }

  @DeleteMapping(value = "/{id}")
  @ResponseStatus(value = HttpStatus.NO_CONTENT)
  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN')")
  public void deleteConsentExemption(@PathVariable Long id) {

    exemptionService.findById(id).ifPresent(exemptionService::remove);
  }

  @GetMapping(value = "/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
  @PreAuthorize("#iam.hasScope('iam:admin.read') or #iam.hasDashboardRole('ROLE_ADMIN')")
  public ConsentExemptionDTO getConsentExemptionById(@PathVariable Long id) {
    ConsentExemption whitelist = exemptionService.findById(id)
        .orElseThrow(
            () -> new EntityNotFoundException("Consent exemption with id " + id + " not found."));
      return ConsentExemptionDTO.from(whitelist);
  }

  @ResponseStatus(code = HttpStatus.NOT_FOUND)
  @ExceptionHandler(EntityNotFoundException.class)
  public ErrorDTO handleNotFoundError(EntityNotFoundException e) {
    return ErrorDTO.fromString(e.getMessage());
  }
}
