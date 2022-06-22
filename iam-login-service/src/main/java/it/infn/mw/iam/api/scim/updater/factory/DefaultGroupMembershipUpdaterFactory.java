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
package it.infn.mw.iam.api.scim.updater.factory;

import static it.infn.mw.iam.api.scim.model.ScimPatchOperation.ScimPatchOperationType.add;
import static it.infn.mw.iam.api.scim.model.ScimPatchOperation.ScimPatchOperationType.remove;

import java.util.List;

import com.google.common.collect.Lists;

import it.infn.mw.iam.api.scim.exception.ScimResourceNotFoundException;
import it.infn.mw.iam.api.scim.model.ScimMemberRef;
import it.infn.mw.iam.api.scim.model.ScimPatchOperation;
import it.infn.mw.iam.api.scim.updater.AccountUpdater;
import it.infn.mw.iam.api.scim.updater.AccountUpdaterFactory;
import it.infn.mw.iam.api.scim.updater.builders.GroupMembershipManagement;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamGroup;

public class DefaultGroupMembershipUpdaterFactory
    implements AccountUpdaterFactory<IamGroup, List<ScimMemberRef>> {

  final IamAccountService accountService;

  public DefaultGroupMembershipUpdaterFactory(IamAccountService accountService) {

    this.accountService = accountService;
  }

  @Override
  public List<AccountUpdater> getUpdatersForPatchOperation(IamGroup group,
      ScimPatchOperation<List<ScimMemberRef>> op) {

    final List<AccountUpdater> updaters = Lists.newArrayList();

    final List<IamAccount> members = memberRefToAccountConverter(op.getValue());

    if (op.getOp().equals(add)) {

      prepareAdders(updaters, members, group);

    }
    if (op.getOp().equals(remove)) {

      prepareRemovers(updaters, members, group);

    }

    return updaters;
  }

  private void prepareAdders(List<AccountUpdater> updaters, List<IamAccount> membersToAdd,
      IamGroup group) {

    for (IamAccount memberToAdd : membersToAdd) {
      GroupMembershipManagement mgmt = new GroupMembershipManagement(memberToAdd, accountService);
      updaters.add(mgmt.addToGroup(group));
    }
  }

  private void prepareRemovers(List<AccountUpdater> updaters, List<IamAccount> membersToRemove,
      IamGroup group) {

    for (IamAccount memberToRemove : membersToRemove) {
      GroupMembershipManagement mgmt =
          new GroupMembershipManagement(memberToRemove, accountService);
      updaters.add(mgmt.removeFromGroup(group));
    }
  }


  private List<IamAccount> memberRefToAccountConverter(List<ScimMemberRef> members) {

    List<IamAccount> newAccounts = Lists.newArrayList();
    if (members == null) {
      return newAccounts;
    }
    for (ScimMemberRef memberRef : members) {
      String uuid = memberRef.getValue();
      IamAccount account = accountService.findByUuid(uuid)
        .orElseThrow(() -> new ScimResourceNotFoundException("User UUID " + uuid + " not found"));
      newAccounts.add(account);
    }
    return newAccounts;
  }

}
