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

import java.util.Date;
import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.data.repository.query.Param;

import it.infn.mw.iam.persistence.model.IamAccessToken;

public interface IamAccessTokenRepository
  extends PagingAndSortingRepository<IamAccessToken, Long> {
  
  @Query("select t from IamAccessToken t where t.tokenValueHash = :atHash")
  Optional<IamAccessToken> findByTokenValue(@Param("atHash") String atHash);

  @Query("select t from IamAccessToken t where t.authenticationHolder.userAuth.name = :userId "
    + "and (t.expiration is NOT NULL and t.expiration > :timestamp)")
  List<IamAccessToken> findValidAccessTokensForUser(
    @Param("userId") String userId, @Param("timestamp") Date timestamp);

  @Query("select t from IamAccessToken t "
    + "where (t.authenticationHolder.userAuth.name = :userId) "
    + "and (t.expiration is NOT NULL and t.expiration > :timestamp) order by t.expiration")
  Page<IamAccessToken> findValidAccessTokensForUser(
    @Param("userId") String userId, @Param("timestamp") Date timestamp,
    Pageable op);

  @Query("select t from IamAccessToken t "
    + "where (t.authenticationHolder.clientId = :clientId) "
    + "and (t.expiration is NOT NULL and t.expiration > :timestamp) order by t.expiration")
  Page<IamAccessToken> findValidAccessTokensForClient(
    @Param("clientId") String clientId, @Param("timestamp") Date timestamp,
    Pageable op);

  @Query("select t from IamAccessToken t "
    + "where (t.authenticationHolder.userAuth.name = :userId) "
    + "and (t.authenticationHolder.clientId = :clientId) "
    + "and (t.expiration is NOT NULL and t.expiration > :timestamp) order by t.expiration")
  Page<IamAccessToken> findValidAccessTokensForUserAndClient(

    @Param("userId") String userId, @Param("clientId") String clientId,

    @Param("timestamp") Date timestamp, Pageable op);

  @Query("select distinct t from IamAccessToken t "
    + "where (t.scope not in ('registration-token', 'resource-token')) "
    + "and (t.expiration is NOT NULL and t.expiration > :timestamp) order by t.expiration ")
  Page<IamAccessToken> findAllValidAccessTokens(
    @Param("timestamp") Date timestamp, Pageable op);

  @Query("select count(t) from IamAccessToken t "
    + "where (t.expiration is NOT NULL and t.expiration > :timestamp)")
  long countValidAccessTokens(@Param("timestamp") Date timestamp);

  @Query("select count(t) from IamAccessToken t "
    + "where (t.expiration is NOT NULL and t.expiration > :timestamp) "
    + "and (t.authenticationHolder.userAuth.name = :userId)")
  long countValidAccessTokensForUser(@Param("userId") String userId,
    @Param("timestamp") Date timestamp);

  @Query("select count(t) from IamAccessToken t "
    + "where (t.expiration is NOT NULL and t.expiration > :timestamp) "
    + "and (t.authenticationHolder.clientId = :clientId)")
  long countValidAccessTokensForClient(@Param("clientId") String clientId,
    @Param("timestamp") Date timestamp);

  @Query("select count(t) from IamAccessToken t "
    + "where (t.expiration is NOT NULL and t.expiration > :timestamp) "
    + "and (t.authenticationHolder.userAuth.name = :userId) "
    + "and (t.authenticationHolder.clientId = :clientId)")
  long countValidAccessTokensForUserAndClient(@Param("userId") String userId,
    @Param("clientId") String clientId, @Param("timestamp") Date timestamp);

  @Query("select t from IamAccessToken t where t.authenticationHolder.id in ("
    + "select sua.id from SavedUserAuthentication sua where sua.name not in ("
    + "select a.username from IamAccount a))")
  List<IamAccessToken> findOrphanedTokens();
}
