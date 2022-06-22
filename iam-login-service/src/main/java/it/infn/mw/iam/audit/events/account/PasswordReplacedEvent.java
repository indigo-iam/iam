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

import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REPLACE_PASSWORD;

import it.infn.mw.iam.api.scim.updater.UpdaterType;
import it.infn.mw.iam.persistence.model.IamAccount;

public class PasswordReplacedEvent extends AccountUpdatedEvent {

  private static final long serialVersionUID = -1656076046003614399L;

  private final String password;

  public PasswordReplacedEvent(Object source, IamAccount account, String password) {
    super(source, account, ACCOUNT_REPLACE_PASSWORD,
        buildMessage(ACCOUNT_REPLACE_PASSWORD, password));
    this.password = password;
  }

  public String getPassword() {
    return password;
  }

  protected static String buildMessage(UpdaterType t, String password) {
    return String.format("%s: %s", t.getDescription(), password);
  }
}
