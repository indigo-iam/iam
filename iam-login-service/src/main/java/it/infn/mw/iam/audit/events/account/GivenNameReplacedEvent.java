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

import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REPLACE_GIVEN_NAME;

import it.infn.mw.iam.api.scim.updater.UpdaterType;
import it.infn.mw.iam.persistence.model.IamAccount;

public class GivenNameReplacedEvent extends AccountUpdatedEvent {

  private static final long serialVersionUID = -8832461145651484401L;

  private final String givenName;

  public GivenNameReplacedEvent(Object source, IamAccount account, String givenName) {
    super(source, account, ACCOUNT_REPLACE_GIVEN_NAME,
        buildMessage(ACCOUNT_REPLACE_GIVEN_NAME, givenName));
    this.givenName = givenName;
  }

  public String getGivenName() {
    return givenName;
  }

  protected static String buildMessage(UpdaterType t, String givenName) {
    return String.format("%s: %s", t.getDescription(), givenName);
  }
}
