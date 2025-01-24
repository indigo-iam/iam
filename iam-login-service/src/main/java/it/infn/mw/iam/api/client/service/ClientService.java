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

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAccountClient;
import it.infn.mw.iam.persistence.model.IamClient;

public interface ClientService {

  Page<IamClient> findAllDynamicallyRegistered(Pageable page);

  Page<IamClient> findAll(Pageable page);

  Optional<IamClient> findClientByClientId(String clientId);

  Optional<IamClient> findClientByClientIdAndAccount(String clientId,
      IamAccount acccount);

  Page<IamAccountClient> findClientOwners(String clientId, Pageable page);

  IamClient linkClientToAccount(IamClient client, IamAccount owner);

  IamClient unlinkClientFromAccount(IamClient client, IamAccount owner);

  IamClient saveNewClient(IamClient client);

  IamClient updateClient(IamClient client);

  IamClient updateClientStatus(IamClient client, boolean status, String userId);

  void deleteClient(IamClient client);

  IamClient setupClientDefaults(IamClient client);

  String generateClientSecret();
}
