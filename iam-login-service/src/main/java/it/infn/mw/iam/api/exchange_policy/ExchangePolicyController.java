/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2019
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
    return service.getTokenExchangePolicies();
  }


  @RequestMapping(value = "/policies/{id}", method = RequestMethod.GET)
  public ExchangePolicyDTO getExchangePolicy(@PathVariable Long id) {
    return service.getTokenExchangePolicyById(id);
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

  @RequestMapping(value = "/policies/clear-cache", method = RequestMethod.POST)
  @ResponseStatus(code = HttpStatus.OK)
  public void invalidateExchangePolicyCache() {
    service.clearTokenExchangePolicyCache();
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
