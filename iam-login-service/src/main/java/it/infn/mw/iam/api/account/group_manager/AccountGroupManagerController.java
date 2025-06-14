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
package it.infn.mw.iam.api.account.group_manager;

import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import it.infn.mw.iam.api.account.authority.AuthorityAlreadyBoundError;
import it.infn.mw.iam.api.account.group_manager.error.InvalidManagedGroupError;
import it.infn.mw.iam.api.account.group_manager.model.AccountManagedGroupsDTO;
import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.api.common.error.NoSuchAccountError;
import it.infn.mw.iam.api.scim.converter.UserConverter;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamGroupRepository;

@RestController
public class AccountGroupManagerController {

  final AccountGroupManagerService service;
  final IamAccountRepository accountRepository;
  final IamGroupRepository groupRepository;
  final UserConverter userConverter;

  public AccountGroupManagerController(AccountGroupManagerService service,
      IamAccountRepository accountRepo, IamGroupRepository groupRepository,
      UserConverter userConverter) {
    this.service = service;
    this.accountRepository = accountRepo;
    this.groupRepository = groupRepository;
    this.userConverter = userConverter;
  }

  @GetMapping(value = "/iam/account/{accountId}/managed-groups")
  @PreAuthorize("#iam.hasScope('iam:admin.read') or #iam.hasDashboardRole('ROLE_ADMIN') or #iam.isUser(#accountId)")
  public AccountManagedGroupsDTO getAccountManagedGroupsInformation(
      @PathVariable String accountId) {
    IamAccount account = accountRepository.findByUuid(accountId)
      .orElseThrow(() -> NoSuchAccountError.forUuid(accountId));

    return service.getManagedGroupInfoForAccount(account);
  }

  @PostMapping(value = "/iam/account/{accountId}/managed-groups/{groupId}")
  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN')")
  @ResponseStatus(value = HttpStatus.CREATED)
  public void addManagedGroupToAccount(@PathVariable String accountId,
      @PathVariable String groupId) {

    IamAccount account = accountRepository.findByUuid(accountId)
      .orElseThrow(() -> NoSuchAccountError.forUuid(accountId));

    IamGroup group = groupRepository.findByUuid(groupId)
      .orElseThrow(() -> InvalidManagedGroupError.groupNotFoundException(groupId));

    service.addManagedGroupForAccount(account, group);
  }

  @DeleteMapping(value = "/iam/account/{accountId}/managed-groups/{groupId}")
  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN')")
  @ResponseStatus(value = HttpStatus.NO_CONTENT)
  public void removeManagedGroupFromAccount(@PathVariable String accountId,
      @PathVariable String groupId) {

    IamAccount account = accountRepository.findByUuid(accountId)
      .orElseThrow(() -> NoSuchAccountError.forUuid(accountId));

    IamGroup group = groupRepository.findByUuid(groupId)
      .orElseThrow(() -> InvalidManagedGroupError.groupNotFoundException(groupId));

    service.removeManagedGroupForAccount(account, group);
  }

  @GetMapping(value = "/iam/group/{groupId}/group-managers")
  @PreAuthorize("#iam.hasScope('iam:admin.read') or #iam.hasAnyDashboardRole('ROLE_ADMIN', 'ROLE_READER') or #iam.isGroupManager(#groupId)")
  public List<ScimUser> getGroupManagersForGroup(@PathVariable String groupId) {
    IamGroup group = groupRepository.findByUuid(groupId)
      .orElseThrow(() -> InvalidManagedGroupError.groupNotFoundException(groupId));

    return service.getGroupManagersForGroup(group)
      .stream()
      .map(userConverter::dtoFromEntity)
      .toList();

  }

  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(NoSuchAccountError.class)
  public ErrorDTO accountNotFoundError(HttpServletRequest req, Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }

  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(InvalidManagedGroupError.class)
  public ErrorDTO invalidManagedGroupError(HttpServletRequest req, Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }
  
  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(AuthorityAlreadyBoundError.class)
  public ErrorDTO alreadyAManagerError(HttpServletRequest req, Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }

}
