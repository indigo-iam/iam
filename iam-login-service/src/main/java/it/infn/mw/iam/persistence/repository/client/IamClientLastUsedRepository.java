/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2023
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

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.data.repository.query.Param;

import it.infn.mw.iam.persistence.model.IamClientLastUsed;

public interface IamClientLastUsedRepository
    extends CrudRepository<IamClientLastUsed, Long>, JpaSpecificationExecutor<IamClientLastUsed> {

  Page<IamClientLastUsed> findByClientId(String clientId, Pageable pageable);

  @Transactional
  @Modifying
  @Query("UPDATE IamClientLastUsed iclu SET iclu.lastUsed = CURRENT_DATE WHERE iclu.client = :clientId")
  void updateLastUsedByClientId(@Param("clientId") String clientId);
}