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

import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import it.infn.mw.iam.api.account.AccountManagementService;
import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.api.common.error.NoSuchAccountError;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@RestController
@RequestMapping(value = AccountAuthorityController.BASE_RESOURCE)
public class AccountAuthorityController {

  public static final String BASE_RESOURCE = "/iam";

  private static final String CAN_MANAGE_ACCOUNT_STATUS =
      "#iam.hasScope('iam:admin.write') or #iam.hasScope('iam:user.write')"
          + " or #iam.hasAnyDashboardRole('ROLE_ADMIN', 'ROLE_USER_MANAGER')";

  final IamAccountRepository iamAccountRepository;
  final AccountAuthorityService authorityService;
  final AccountManagementService managementService;

  public AccountAuthorityController(IamAccountRepository iamRepo, AccountAuthorityService aas,
      AccountManagementService managementService) {
    this.iamAccountRepository = iamRepo;
    this.authorityService = aas;
    this.managementService = managementService;
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

  @PreAuthorize("hasRole('ROLE_USER')")
  @GetMapping(value = "/me/authorities")
  public AuthoritySetDTO getAuthoritiesForMe(Authentication authn) {
    return AuthoritySetDTO
      .fromAuthorities(authorityService.getAccountAuthorities(findAccountByName(authn.getName())));
  }

  @PreAuthorize("#iam.hasScope('iam:admin.read') or #iam.hasScope('iam:user.read') or #iam.hasAnyDashboardRole('ROLE_ADMIN', 'ROLE_GM', 'ROLE_READER', 'ROLE_USER_MANAGER')")
  @GetMapping(value = "/account/{id}/authorities")
  @ResponseBody
  public AuthoritySetDTO getAuthoritiesForAccount(@PathVariable("id") String id) {
    return AuthoritySetDTO
      .fromAuthorities(authorityService.getAccountAuthorities(findAccountById(id)));
  }

  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN')")
  @PostMapping(value = "/account/{id}/authorities")
  public void addAuthorityToAccount(@PathVariable("id") String id, @Valid AuthorityDTO authority,
      BindingResult validationResult) {

    if (validationResult.hasErrors()) {
      throw buildValidationError(validationResult);
    }

    authorityService.addAuthorityToAccount(findAccountById(id), authority.getAuthority());

  }

  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN')")
  @DeleteMapping(value = "/account/{id}/authorities")
  public void removeAuthorityFromAccount(@PathVariable("id") String id,
      @Valid AuthorityDTO authority, BindingResult validationResult) {

    if (validationResult.hasErrors()) {
      throw buildValidationError(validationResult);
    }

    authorityService.removeAuthorityFromAccount(findAccountById(id), authority.getAuthority());
  }

  @GetMapping("/account/reserved")
  @PreAuthorize("#iam.hasScope('iam:admin.read') or #iam.hasScope('iam:user.read')"
      + " or #iam.hasAnyDashboardRole('ROLE_ADMIN', 'ROLE_USER_MANAGER')")
  public Set<String> getAccountsReservedToAdministrators() {
    return managementService.getAccountsReservedToAdministrators();
  }

  @PatchMapping("/account/{id}/enable")
  @PreAuthorize(CAN_MANAGE_ACCOUNT_STATUS)
  public void enableAccount(@PathVariable String id) {
    managementService.enableAccount(id);
  }

  @PatchMapping("/account/{id}/disable")
  @PreAuthorize(CAN_MANAGE_ACCOUNT_STATUS)
  public void disableAccount(@PathVariable String id) {
    managementService.disableAccount(id);
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
