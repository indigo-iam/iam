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

import java.util.Date;
import java.util.List;
import java.util.Optional;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.data.repository.query.Param;

public interface IamClientRepository extends PagingAndSortingRepository<ClientDetailsEntity, Long>,
    JpaSpecificationExecutor<ClientDetailsEntity> {

  Optional<ClientDetailsEntity> findByClientId(String clientId);

  List<ClientDetailsEntity> findByClientNameLike(String clientName);

  @Query("select c from ClientDetailsEntity c join ClientRelyingPartyEntity e where e.expiration < :dateTime")
  List<ClientDetailsEntity> findByExpirationBefore(@Param("dateTime") Date dateTime);

  @Query("select e.client from ClientRelyingPartyEntity e where e.entityId = :entityId")
  Optional<ClientDetailsEntity> findByEntityId(@Param("entityId") String entityId);
}
