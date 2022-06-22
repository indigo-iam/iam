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
package it.infn.mw.iam.api.client.service;

import java.util.Optional;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAccountClient;

public interface ClientService {

  Page<ClientDetailsEntity> findAllDynamicallyRegistered(Pageable page);

  Page<ClientDetailsEntity> findAll(Pageable page);

  Optional<ClientDetailsEntity> findClientByClientId(String clientId);

  Optional<ClientDetailsEntity> findClientByClientIdAndAccount(String clientId,
      IamAccount acccount);

  Page<IamAccountClient> findClientOwners(String clientId, Pageable page);

  ClientDetailsEntity linkClientToAccount(ClientDetailsEntity client, IamAccount owner);

  ClientDetailsEntity unlinkClientFromAccount(ClientDetailsEntity client, IamAccount owner);

  ClientDetailsEntity saveNewClient(ClientDetailsEntity client);

  ClientDetailsEntity updateClient(ClientDetailsEntity client);

  void deleteClient(ClientDetailsEntity client);

}
