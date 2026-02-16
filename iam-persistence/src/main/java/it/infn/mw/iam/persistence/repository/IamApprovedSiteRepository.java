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
package it.infn.mw.iam.persistence.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import it.infn.mw.iam.persistence.model.ApprovedSite;

public interface IamApprovedSiteRepository extends JpaRepository<ApprovedSite, Long> {

  @Query("""
      SELECT a
      FROM ApprovedSite a
      WHERE a.client.clientId = :clientId
        AND a.account.username = :userId
    """)
  List<ApprovedSite> findByClientIdAndUserId(String clientId, String userId);

  @Query("""
      SELECT a
      FROM ApprovedSite a
      WHERE a.account.username = :userId
    """)
  List<ApprovedSite> findByUserId(String userId);

  @Query("""
      SELECT a
      FROM ApprovedSite a
      WHERE a.client.clientId = :clientId
    """)
  List<ApprovedSite> findByClientId(String clientId);

  @Query("""
        SELECT a
        FROM ApprovedSite a
        WHERE a.timeoutDate IS NOT NULL
          AND a.timeoutDate < CURRENT_TIMESTAMP
      """)
  List<ApprovedSite> findExpired();

  @Query("""
        SELECT
          COUNT(DISTINCT a.account.id) AS userCount,
          COUNT(DISTINCT a.client.id) AS clientCount
        FROM ApprovedSite a
      """)
  UserClientCounts findDistinctUserAndClientCounts();
}
