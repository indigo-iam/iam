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
package it.infn.mw.iam.api.account.status;

import java.util.function.Supplier;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.api.common.error.NoSuchAccountError;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;

@RestController
@RequestMapping(value = AccountStatusController.BASE_RESOURCE)
public class AccountStatusController {

  public static final String BASE_RESOURCE = "/iam/account/{id}";

  private final IamAccountService accountService;

  public AccountStatusController(IamAccountService accountService) {
    this.accountService = accountService;
  }

  private Supplier<NoSuchAccountError> noSuchAccountError(String uuid) {
    return () -> NoSuchAccountError.forUuid(uuid);
  }

  @PatchMapping("/enable")
  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN')"
      + " or ((#iam.hasScope('iam:user.write') or #iam.hasDashboardRole('ROLE_USER_MANAGER'))"
      + " and #iam.canManageAccount(#id))")
  public void enableAccount(@PathVariable String id) {
    IamAccount account = accountService.findByUuid(id).orElseThrow(noSuchAccountError(id));
    if (!account.isActive()) {
      accountService.restoreAccount(account);
    }
  }

  @PatchMapping("/disable")
  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN')"
      + " or ((#iam.hasScope('iam:user.write') or #iam.hasDashboardRole('ROLE_USER_MANAGER'))"
      + " and #iam.canManageAccount(#id))")
  public void disableAccount(@PathVariable String id) {
    IamAccount account = accountService.findByUuid(id).orElseThrow(noSuchAccountError(id));
    if (account.isActive()) {
      accountService.disableAccount(account);
    }
  }

  @ResponseStatus(code = HttpStatus.NOT_FOUND)
  @ExceptionHandler(NoSuchAccountError.class)
  public ErrorDTO handleNotFoundError(NoSuchAccountError e) {
    return ErrorDTO.fromString(e.getMessage());
  }

}
