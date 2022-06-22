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
package it.infn.mw.iam.audit.events.account.group;

import it.infn.mw.iam.api.scim.updater.UpdaterType;
import it.infn.mw.iam.audit.events.account.AccountUpdatedEvent;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamGroup;

public abstract class GroupMembershipUpdatedEvent extends AccountUpdatedEvent {

  private static final long serialVersionUID = 1L;

  private final IamGroup group;

  public GroupMembershipUpdatedEvent(Object source, IamAccount account, UpdaterType type,
      IamGroup group) {
    super(source, account, type, buildMessage(type, account, group));
    this.group = group;
  }

  protected IamGroup getGroup() {
    return group;
  }


  protected static String buildMessage(UpdaterType t, IamAccount account,
      IamGroup group) {
    return String.format(t.getDescription(), account.getUsername(),
        group.getName());
  }

}
