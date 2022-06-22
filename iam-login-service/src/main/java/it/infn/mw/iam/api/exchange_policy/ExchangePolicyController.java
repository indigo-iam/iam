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
package it.infn.mw.iam.api.exchange_policy;

import java.util.List;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import it.infn.mw.iam.api.common.ErrorDTO;

@RestController
@RequestMapping("/iam/api/exchange")
@PreAuthorize("hasRole('ADMIN')")
public class ExchangePolicyController {

  private final TokenExchangePolicyService service;

  private static final int UNPAGED_PAGE_SIZE = 1000;

  private static final Pageable UNPAGED = Pageable.unpaged();

  private static final String UNPAGED_ERROR_MSG = String.format(
      "More than %d exchange policies found, but only the first %d will be returned. it's time to properly implement pagination",
      UNPAGED_PAGE_SIZE, UNPAGED_PAGE_SIZE);


  @Autowired
  public ExchangePolicyController(TokenExchangePolicyService service) {
    this.service = service;
  }

  protected InvalidExchangePolicyError buildValidationError(BindingResult result) {
    String firstErrorMessage = result.getAllErrors().get(0).getDefaultMessage();
    return new InvalidExchangePolicyError(firstErrorMessage);
  }

  @RequestMapping(value = "/policies", method = RequestMethod.GET)
  public List<ExchangePolicyDTO> getExchangePolicies() {
    Page<ExchangePolicyDTO> resultsPage = service.getTokenExchangePolicies(UNPAGED);
    if (resultsPage.hasNext()) {
      throw new IllegalStateException(UNPAGED_ERROR_MSG);
    }

    return resultsPage.getContent();
  }

  @RequestMapping(value = "/policies/{id}", method = RequestMethod.DELETE)
  @ResponseStatus(code = HttpStatus.NO_CONTENT)
  public void deleteExchangePolicy(@PathVariable Long id) {
    service.deleteTokenExchangePolicyById(id);
  }

  @RequestMapping(value = "/policies", method = RequestMethod.POST)
  @ResponseStatus(code = HttpStatus.CREATED)
  public void createExchangePolicy(@Valid @RequestBody ExchangePolicyDTO dto,
      BindingResult validationResult) {

    if (validationResult.hasErrors()) {
      throw buildValidationError(validationResult);
    }

    service.createTokenExchangePolicy(dto);
  }


  @ResponseStatus(value = HttpStatus.NOT_IMPLEMENTED)
  @ExceptionHandler(IllegalStateException.class)
  public ErrorDTO notImplementedError(Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }

  @ResponseStatus(value = HttpStatus.NOT_FOUND)
  @ExceptionHandler(ExchangePolicyNotFoundError.class)
  public ErrorDTO notFoundError(Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }

  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(InvalidExchangePolicyError.class)
  public ErrorDTO invalidPolicy(Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }

  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(HttpMessageNotReadableException.class)
  public ErrorDTO invalidRequestBody(Exception ex) {
    return ErrorDTO
      .fromString("Invalid token exchange policy: could not parse the policy JSON representation");
  }

}
