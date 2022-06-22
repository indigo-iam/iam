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
package it.infn.mw.iam.api.account.authority;

import static java.lang.String.format;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.api.common.error.NoSuchAccountError;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@RestController
@RequestMapping(value = AccountAuthorityController.BASE_RESOURCE)
public class AccountAuthorityController {

  public static final String BASE_RESOURCE = "/iam";

  final IamAccountRepository iamAccountRepository;
  final AccountAuthorityService authorityService;

  @Autowired
  public AccountAuthorityController(IamAccountRepository iamRepo, AccountAuthorityService aas) {
    this.iamAccountRepository = iamRepo;
    this.authorityService = aas;
  }

  protected InvalidAuthorityError buildValidationError(BindingResult result) {
    String firstErrorMessage = result.getAllErrors().get(0).getDefaultMessage();
    return new InvalidAuthorityError(firstErrorMessage);
  }

  protected IamAccount findAccountById(String id) {
    return iamAccountRepository.findByUuid(id)
      .orElseThrow(() -> new NoSuchAccountError(format("No account found for id '%s'", id)));
  }

  protected IamAccount findAccountByName(String name) {
    return iamAccountRepository.findByUsername(name)
      .orElseThrow(() -> new NoSuchAccountError(format("No account found for name '%s'", name)));
  }

  @PreAuthorize("hasRole('USER')")
  @RequestMapping(value = "/me/authorities", method = RequestMethod.GET)
  public AuthoritySetDTO getAuthoritiesForMe(Authentication authn) {
    return AuthoritySetDTO
      .fromAuthorities(authorityService.getAccountAuthorities(findAccountByName(authn.getName())));
  }

  @PreAuthorize("hasRole('ADMIN')")
  @RequestMapping(value = "/account/{id}/authorities", method = RequestMethod.GET)
  @ResponseBody
  public AuthoritySetDTO getAuthoritiesForAccount(@PathVariable("id") String id) {
    return AuthoritySetDTO
      .fromAuthorities(authorityService.getAccountAuthorities(findAccountById(id)));
  }

  @PreAuthorize("hasRole('ADMIN')")
  @RequestMapping(value = "/account/{id}/authorities", method = RequestMethod.POST)
  public void addAuthorityToAccount(@PathVariable("id") String id, @Valid AuthorityDTO authority,
      BindingResult validationResult) {

    if (validationResult.hasErrors()) {
      throw buildValidationError(validationResult);
    }

    authorityService.addAuthorityToAccount(findAccountById(id), authority.getAuthority());

  }

  @PreAuthorize("hasRole('ADMIN')")
  @RequestMapping(value = "/account/{id}/authorities", method = RequestMethod.DELETE)
  public void removeAuthorityFromAccount(@PathVariable("id") String id,
      @Valid AuthorityDTO authority, BindingResult validationResult) {

    if (validationResult.hasErrors()) {
      throw buildValidationError(validationResult);
    }

    authorityService.removeAuthorityFromAccount(findAccountById(id), authority.getAuthority());
  }

  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(InvalidAuthorityError.class)
  public ErrorDTO authorityValidationError(HttpServletRequest req, Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }

  @ResponseStatus(value = HttpStatus.NOT_FOUND)
  @ExceptionHandler(NoSuchAccountError.class)
  public ErrorDTO accountNotFoundError(HttpServletRequest req, Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }

  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(AuthorityAlreadyBoundError.class)
  public ErrorDTO authorityAlreadyBoundError(HttpServletRequest req, Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }


}
