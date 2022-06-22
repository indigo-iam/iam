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
package it.infn.mw.iam.persistence.repository.client;

import java.util.Optional;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAccountClient;

public interface IamAccountClientRepository
    extends CrudRepository<IamAccountClient, Long>, JpaSpecificationExecutor<IamAccountClient> {

  @Query("select ac.client from IamAccountClient ac where ac.client.clientId = :clientId")
  Page<ClientDetailsEntity> findClientByClientClientId(String clientId, Pageable pageable);

  @Query("select ac.client from IamAccountClient ac where ac.account = :account")
  Page<ClientDetailsEntity> findClientByAccount(IamAccount account, Pageable pageable);

  Page<IamAccountClient> findByClientClientId(String clientId, Pageable pageable);

  Page<IamAccountClient> findByAccount(IamAccount account, Pageable pageable);

  Page<IamAccountClient> findByAccountUsername(String username, Pageable pageable);

  Page<IamAccountClient> findByAccountUuid(String uuid, Pageable pageable);

  Optional<IamAccountClient> findByAccountAndClient(IamAccount account, ClientDetailsEntity client);

  Optional<IamAccountClient> findByAccountAndClientId(IamAccount account, long clientId);

  void deleteByClientId(long clientId);

  void deleteByAccount(IamAccount account);

  void deleteByAccountAndClientId(IamAccount account, long clientId);

}
