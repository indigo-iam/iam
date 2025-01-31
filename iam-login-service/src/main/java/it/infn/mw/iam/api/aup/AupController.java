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
package it.infn.mw.iam.api.aup;

import javax.validation.Valid;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import it.infn.mw.iam.api.aup.error.AupAlreadyExistsError;
import it.infn.mw.iam.api.aup.error.AupNotFoundError;
import it.infn.mw.iam.api.aup.error.InvalidAupError;
import it.infn.mw.iam.api.aup.model.AupConverter;
import it.infn.mw.iam.api.aup.model.AupDTO;
import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.persistence.model.IamAup;

@RestController
@Transactional
public class AupController {

  private final AupService service;
  private final AupConverter converter;

  public AupController(AupService service, AupConverter converter) {
    this.service = service;
    this.converter = converter;

  }

  private RuntimeException buildValidationError(BindingResult validationResult) {
    String firstErrorMessage = validationResult.getAllErrors().get(0).getDefaultMessage();
    return new InvalidAupError(firstErrorMessage);
  }

  @GetMapping(value = "/iam/aup")
  public AupDTO getAup() {
    IamAup aup = service.findAup().orElseThrow(AupNotFoundError::new);

    return converter.dtoFromEntity(aup);
  }

  @PostMapping(value = "/iam/aup")
  @ResponseStatus(code = HttpStatus.CREATED)
  @PreAuthorize("#iam.hasDashboardRole('ROLE_ADMIN') or #iam.hasScope('iam:admin.write')")
  public void createAup(@Valid @RequestBody AupDTO aup, BindingResult validationResult) {
    if (service.findAup().isPresent()) {
      throw new AupAlreadyExistsError();
    }

    if (validationResult.hasErrors()) {
      throw buildValidationError(validationResult);
    }

    service.saveAup(aup);
  }

  @PatchMapping(value = "/iam/aup")
  @ResponseStatus(code = HttpStatus.OK)
  @PreAuthorize("#iam.hasDashboardRole('ROLE_ADMIN') or #iam.hasScope('iam:admin.write')")
  public AupDTO updateAup(@Valid @RequestBody AupDTO aup, BindingResult validationResult) {

    if (validationResult.hasErrors()) {
      throw buildValidationError(validationResult);
    }

    IamAup updatedAup = service.updateAup(aup);
    return converter.dtoFromEntity(updatedAup);
  }

  @PostMapping(value = "/iam/aup/touch")
  @ResponseStatus(code = HttpStatus.OK)
  @PreAuthorize("#iam.hasDashboardRole('ROLE_ADMIN') or #iam.hasScope('iam:admin.write')")
  public AupDTO touchAup() {

    IamAup updatedAup = service.touchAup();
    return converter.dtoFromEntity(updatedAup);
  }

  @DeleteMapping(value = "/iam/aup")
  @ResponseStatus(code = HttpStatus.NO_CONTENT)
  @PreAuthorize("#iam.hasDashboardRole('ROLE_ADMIN') or #iam.hasScope('iam:admin.write')")
  public void deleteAup() {
    service.deleteAup();
  }

  @ResponseStatus(value = HttpStatus.CONFLICT)
  @ExceptionHandler(AupAlreadyExistsError.class)
  public ErrorDTO aupAlreadyExistsError(Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }

  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(InvalidAupError.class)
  public ErrorDTO invalidAupError(Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }

  @ResponseStatus(value = HttpStatus.NOT_FOUND)
  @ExceptionHandler(AupNotFoundError.class)
  public ErrorDTO notFoundError(Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }
  
  @ResponseStatus(value = HttpStatus.FORBIDDEN)
  @ExceptionHandler(AccessDeniedException.class)
  public ErrorDTO accessDeniedError(Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }
}
