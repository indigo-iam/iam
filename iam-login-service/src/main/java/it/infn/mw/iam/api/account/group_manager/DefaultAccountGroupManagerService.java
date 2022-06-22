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

import static java.lang.String.format;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.google.common.collect.Lists;

import it.infn.mw.iam.api.account.authority.AccountAuthorityService;
import it.infn.mw.iam.api.account.group_manager.error.InvalidManagedGroupError;
import it.infn.mw.iam.api.account.group_manager.model.AccountManagedGroupsDTO;
import it.infn.mw.iam.api.common.GroupDTO;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAuthority;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamGroupRepository;

@Service
public class DefaultAccountGroupManagerService implements AccountGroupManagerService {

  public static final String ROLE_GM_TEMPLATE = "ROLE_GM:%s";
  
  final IamAccountRepository accountRepo;
  final IamGroupRepository groupRepo;
  final AccountAuthorityService authorityService;


  @Autowired
  public DefaultAccountGroupManagerService(IamAccountRepository accountRepo,
      IamGroupRepository groupRepo, AccountAuthorityService authorityService) {
    this.accountRepo = accountRepo;
    this.groupRepo = groupRepo;
    this.authorityService = authorityService;
  }

  private List<GroupDTO> iamGroupsToDTO(List<IamGroup> groups) {
    List<GroupDTO> result = new ArrayList<>();

    for (IamGroup g : groups) {
      result.add(GroupDTO.builder().id(g.getUuid()).name(g.getName()).build());
    }

    return result;
  }

  @Override
  public void addManagedGroupForAccount(IamAccount account, IamGroup group) {

    authorityService.addAuthorityToAccount(account, format(ROLE_GM_TEMPLATE, group.getUuid()));

  }

  @Override
  public void removeManagedGroupForAccount(IamAccount account, IamGroup group) {

    authorityService.removeAuthorityFromAccount(account, format(ROLE_GM_TEMPLATE, group.getUuid()));
  }


  @Override
  public AccountManagedGroupsDTO getManagedGroupInfoForAccount(IamAccount account) {
    AccountManagedGroupsDTO.Builder result = AccountManagedGroupsDTO.builder();
    result.id(account.getUuid());
    result.username(account.getUsername());

    List<IamGroup> managedGroups = new ArrayList<>();

    account.getAuthorities().stream().filter(IamAuthority::isGroupManagerAuthority).forEach(a -> {
      String groupId = a.getManagedGroupId();
      managedGroups.add(groupRepo.findByUuid(groupId)
        .orElseThrow(() -> InvalidManagedGroupError.groupNotFoundException(groupId)));
    });

    result.managedGroups(iamGroupsToDTO(managedGroups));

    List<IamGroup> unmanagedGroups = null;

    if (managedGroups.isEmpty()) {
      unmanagedGroups = Lists.newArrayList(groupRepo.findAll());
    } else {
      unmanagedGroups = groupRepo
        .findByUuidNotIn(managedGroups.stream().map(IamGroup::getUuid).collect(Collectors.toSet()));
    }
    result.unmanagedGroups(iamGroupsToDTO(unmanagedGroups));

    return result.build();
  }

  @Override
  public List<IamAccount> getGroupManagersForGroup(IamGroup group) {
    return accountRepo.findByAuthority(format(ROLE_GM_TEMPLATE, group.getUuid()));
  }

}
