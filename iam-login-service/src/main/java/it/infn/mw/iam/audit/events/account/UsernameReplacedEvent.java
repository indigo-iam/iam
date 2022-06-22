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
package it.infn.mw.iam.audit.events.account;

import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REPLACE_USERNAME;

import it.infn.mw.iam.api.scim.updater.UpdaterType;
import it.infn.mw.iam.persistence.model.IamAccount;

public class UsernameReplacedEvent extends AccountUpdatedEvent {

  private static final long serialVersionUID = -4559709075463515934L;

  private final String username;

  public UsernameReplacedEvent(Object source, IamAccount account, String username) {
    super(source, account, ACCOUNT_REPLACE_USERNAME,
        buildMessage(ACCOUNT_REPLACE_USERNAME, username));
    this.username = username;
  }

  public String getUsername() {
    return username;
  }

  protected static String buildMessage(UpdaterType t, String username) {
    return String.format("%s: %s", t.getDescription(), username);
  }
}
