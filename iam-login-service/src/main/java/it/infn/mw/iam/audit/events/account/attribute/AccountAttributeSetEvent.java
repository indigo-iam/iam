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
package it.infn.mw.iam.audit.events.account.attribute;

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAttribute;

public class AccountAttributeSetEvent extends AccountAttributeEvent {

  private static final long serialVersionUID = 1L;

  public static final String MESSAGE = "Attribute '%s' set for account '%s'";

  public AccountAttributeSetEvent(Object source, IamAccount account, IamAttribute attribute) {
    super(source, account, attribute,
        String.format(MESSAGE, attribute.getName(), account.getUsername()));
  }

}
