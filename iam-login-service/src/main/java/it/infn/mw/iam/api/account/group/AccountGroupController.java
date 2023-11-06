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
package it.infn.mw.iam.api.account.group;

import static it.infn.mw.iam.api.account.group.ErrorSuppliers.noSuchAccount;
import static it.infn.mw.iam.api.account.group.ErrorSuppliers.noSuchGroup;
import static org.springframework.web.bind.annotation.RequestMethod.DELETE;
import static org.springframework.web.bind.annotation.RequestMethod.POST;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.api.common.error.NoSuchAccountError;
import it.infn.mw.iam.api.requests.service.GroupRequestsService;
import it.infn.mw.iam.core.group.IamGroupService;
import it.infn.mw.iam.core.group.error.NoSuchGroupError;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.model.IamGroupRequest;

@RestController
public class AccountGroupController {

  private final IamAccountService accountService;
  private final IamGroupService groupService;
  private final GroupRequestsService groupRequestsService;

  @Autowired
  public AccountGroupController(IamAccountService accountService, IamGroupService groupService, GroupRequestsService groupRequestsService) {
    this.accountService = accountService;
    this.groupService = groupService;
    this.groupRequestsService = groupRequestsService;
  }

  @RequestMapping(value = "/iam/account/{accountUuid}/groups/{groupUuid}", method = POST)
  @ResponseStatus(value = HttpStatus.CREATED)
  @PreAuthorize("#iam.hasAdminOrGMDashboardRoleOfGroup(#groupUuid) or #iam.hasScope('iam:admin.write')")
  public void addAccountToGroup(@PathVariable String accountUuid, @PathVariable String groupUuid) {
    IamGroup group = groupService.findByUuid(groupUuid).orElseThrow(noSuchGroup(groupUuid));

    IamAccount account =
        accountService.findByUuid(accountUuid).orElseThrow(noSuchAccount(accountUuid));

    accountService.addToGroup(account, group);

    for (IamGroupRequest r : group.getGroupRequests()) {
      if (accountUuid.equals(r.getAccount().getUuid())) {
        groupRequestsService.deleteGroupRequest(r.getUuid());
      }
    }
  }

  @RequestMapping(value = "/iam/account/{accountUuid}/groups/{groupUuid}", method = DELETE)
  @ResponseStatus(value = HttpStatus.NO_CONTENT)
  @PreAuthorize("#iam.hasAdminOrGMDashboardRoleOfGroup(#groupUuid) or #iam.hasScope('iam:admin.write')")
  public void removeAccountFromGroup(@PathVariable String accountUuid,
      @PathVariable String groupUuid) {
    IamGroup group = groupService.findByUuid(groupUuid).orElseThrow(noSuchGroup(groupUuid));

    IamAccount account =
        accountService.findByUuid(accountUuid).orElseThrow(noSuchAccount(accountUuid));

    accountService.removeFromGroup(account, group);
  }

  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(NoSuchAccountError.class)
  public ErrorDTO noSuchAccountError(HttpServletRequest req, Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }

  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(NoSuchGroupError.class)
  public ErrorDTO noSuchGroupError(HttpServletRequest req, Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }

  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(AlreadyMemberError.class)
  public ErrorDTO alreadyMemberError(HttpServletRequest req, Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }

  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(NotAMemberError.class)
  public ErrorDTO notAMemberError(HttpServletRequest req, Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }
}
