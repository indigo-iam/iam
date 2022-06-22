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

import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.data.repository.query.Param;

public interface IamOAuthRefreshTokenRepository
    extends PagingAndSortingRepository<OAuth2RefreshTokenEntity, Long> {

  @Query("select t from OAuth2RefreshTokenEntity t where t.authenticationHolder.userAuth.name = :userId "
      + "and (t.expiration is NULL or t.expiration > :timestamp)")
  List<OAuth2RefreshTokenEntity> findValidRefreshTokensForUser(@Param("userId") String userId,
      @Param("timestamp") Date timestamp);

  @Query("select t from OAuth2RefreshTokenEntity t "
      + "where (t.authenticationHolder.userAuth.name = :userId) "
      + "and (t.expiration is NULL or t.expiration > :timestamp) order by t.expiration,t.id")
  Page<OAuth2RefreshTokenEntity> findValidRefreshTokensForUser(@Param("userId") String userId,
      @Param("timestamp") Date timestamp, Pageable op);

  @Query("select t from OAuth2RefreshTokenEntity t "
      + "where (t.authenticationHolder.clientId = :clientId) "
      + "and (t.expiration is NULL or t.expiration > :timestamp) order by t.expiration,t.id")
  Page<OAuth2RefreshTokenEntity> findValidRefreshTokensForClient(@Param("clientId") String clientId,
      @Param("timestamp") Date timestamp, Pageable op);

  @Query("select t from OAuth2RefreshTokenEntity t "
      + "where (t.authenticationHolder.userAuth.name = :userId) "
      + "and (t.authenticationHolder.clientId = :clientId) "
      + "and (t.expiration is NULL or t.expiration > :timestamp) order by t.expiration,t.id")
  Page<OAuth2RefreshTokenEntity> findValidRefreshTokensForUserAndClient(
      @Param("userId") String userId, @Param("clientId") String clientId,
      @Param("timestamp") Date timestamp, Pageable op);

  @Query("select t from OAuth2RefreshTokenEntity t "
      + "where (t.expiration is NULL or t.expiration > :timestamp) order by t.expiration,t.id")
  Page<OAuth2RefreshTokenEntity> findAllValidRefreshTokens(@Param("timestamp") Date timestamp,
      Pageable op);

  @Query("select count(t) from OAuth2RefreshTokenEntity t "
      + "where (t.expiration is NULL or t.expiration > :timestamp)")
  long countValidRefreshTokens(@Param("timestamp") Date timestamp);

  @Query("select count(t) from OAuth2RefreshTokenEntity t "
      + "where (t.expiration is NULL or t.expiration > :timestamp) "
      + "and (t.authenticationHolder.userAuth.name = :userId)")
  long countValidRefreshTokensForUser(@Param("userId") String userId,
      @Param("timestamp") Date timestamp);

  @Query("select count(t) from OAuth2RefreshTokenEntity t "
      + "where (t.expiration is NULL or t.expiration > :timestamp) "
      + "and (t.authenticationHolder.clientId = :clientId)")
  long countValidRefreshTokensForClient(@Param("clientId") String clientId,
      @Param("timestamp") Date timestamp);

  @Query("select count(t) from OAuth2RefreshTokenEntity t "
      + "where (t.expiration is NULL or t.expiration > :timestamp) "
      + "and (t.authenticationHolder.userAuth.name = :userId) "
      + "and (t.authenticationHolder.clientId = :clientId)")
  long countValidRefreshTokensForUserAndClient(@Param("userId") String userId,
      @Param("clientId") String clientId, @Param("timestamp") Date timestamp);

  @Query("select t from OAuth2RefreshTokenEntity t where t.authenticationHolder.id in ("
      + "select sua.id from SavedUserAuthentication sua where sua.name not in ("
      + "select a.username from IamAccount a))")
  List<OAuth2RefreshTokenEntity> findOrphanedTokens();
}
