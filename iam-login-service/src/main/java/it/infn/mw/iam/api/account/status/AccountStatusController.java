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

import java.util.Set;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import it.infn.mw.iam.api.account.AccountManagementService;
import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.api.common.error.NoSuchAccountError;

@RestController
@RequestMapping(value = AccountStatusController.BASE_RESOURCE)
public class AccountStatusController {

  public static final String BASE_RESOURCE = "/iam/account";

  private static final String CAN_MANAGE_ACCOUNT_STATUS =
      "#iam.hasScope('iam:admin.write') or #iam.hasScope('iam:user.write')"
          + " or #iam.hasAnyDashboardRole('ROLE_ADMIN', 'ROLE_USER_MANAGER')";

  private final AccountManagementService service;

  public AccountStatusController(AccountManagementService service) {
    this.service = service;
  }

  @GetMapping("/reserved")
  @PreAuthorize("#iam.hasScope('iam:admin.read') or #iam.hasScope('iam:user.read')"
      + " or #iam.hasAnyDashboardRole('ROLE_ADMIN', 'ROLE_USER_MANAGER')")
  public Set<String> getAccountsReservedToAdministrators() {
    return service.getAccountsReservedToAdministrators();
  }

  @PatchMapping("/{id}/enable")
  @PreAuthorize(CAN_MANAGE_ACCOUNT_STATUS)
  public void enableAccount(@PathVariable String id) {
    service.enableAccount(id);
  }

  @PatchMapping("/{id}/disable")
  @PreAuthorize(CAN_MANAGE_ACCOUNT_STATUS)
  public void disableAccount(@PathVariable String id) {
    service.disableAccount(id);
  }

  @ResponseStatus(code = HttpStatus.NOT_FOUND)
  @ExceptionHandler(NoSuchAccountError.class)
  public ErrorDTO handleNotFoundError(NoSuchAccountError e) {
    return ErrorDTO.fromString(e.getMessage());
  }

}
