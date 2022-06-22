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
package it.infn.mw.iam.audit.events.account.client;

import org.mitre.oauth2.model.ClientDetailsEntity;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import it.infn.mw.iam.audit.events.account.AccountEvent;
import it.infn.mw.iam.audit.utils.IamClientSerializer;
import it.infn.mw.iam.persistence.model.IamAccount;

public abstract class AccountClientEvent extends AccountEvent {

  private static final long serialVersionUID = 1L;

  @JsonSerialize(using = IamClientSerializer.class)
  private final ClientDetailsEntity client;

  public AccountClientEvent(Object source, IamAccount account, ClientDetailsEntity client,
      String message) {
    super(source, account, message);
    this.client = client;
  }

  public ClientDetailsEntity getClient() {
    return client;
  }
}
