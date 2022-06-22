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
package it.infn.mw.iam.audit.events.account.ssh;

import java.util.Collection;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import it.infn.mw.iam.api.scim.updater.UpdaterType;
import it.infn.mw.iam.audit.events.account.AccountUpdatedEvent;
import it.infn.mw.iam.audit.utils.IamSshKeySerializer;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamSshKey;

public abstract class SshKeyUpdatedEvent extends AccountUpdatedEvent {

  private static final long serialVersionUID = 1L;

  @JsonSerialize(using = IamSshKeySerializer.class)
  private final Collection<IamSshKey> sshKeys;

  public SshKeyUpdatedEvent(Object source, IamAccount account, UpdaterType type,
      Collection<IamSshKey> sshKeys) {
    super(source, account, type, buildMessage(type, account, sshKeys));
    this.sshKeys = sshKeys;
  }

  protected Collection<IamSshKey> getSshKeys() {
    return sshKeys;
  }

  protected static String buildMessage(UpdaterType t, IamAccount account,
      Collection<IamSshKey> sshKeys) {
    return String.format("%s: username: '%s' values: '%s'", t.getDescription(),
        account.getUsername(), sshKeys);
  }

}
