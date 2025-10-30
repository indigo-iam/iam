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

import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.data.repository.query.Param;

public interface IamOAuthAccessTokenRepository
    extends PagingAndSortingRepository<OAuth2AccessTokenEntity, Long> {

  // @formatter:off
  @Query("select t from OAuth2AccessTokenEntity t "
      + "where t.tokenValueHash = :atHash")
  Optional<OAuth2AccessTokenEntity> findByTokenValue(@Param("atHash") String atHash);

  @Query("select t from OAuth2AccessTokenEntity t "
      + "where t.client.id = :clientId "
      + "and ('registration-token' member of t.scope or 'resource-token' member of t.scope)")
  Optional<OAuth2AccessTokenEntity> findRegistrationToken(@Param("clientId") Long id);

  @Query("select t from OAuth2AccessTokenEntity t "
      + "where t.client.id = :clientId "
      + "and 'resource-token' not member of t.scope "
      + "and 'registration-token' not member of t.scope")
  List<OAuth2AccessTokenEntity> findAccessTokens(@Param("clientId") Long id);

  @Query("select t from OAuth2AccessTokenEntity t "
      + "where t.refreshToken.id = :rtId")
  List<OAuth2AccessTokenEntity> findAccessTokensForRefreshToken(@Param("rtId") Long refreshTokenId);

  @Query("select t from OAuth2AccessTokenEntity t "
      + "where t.authenticationHolder.userAuth.name = :userId "
      + "and t.expiration is NOT NULL "
      + "and t.expiration > :timestamp "
      + "and 'resource-token' not member of t.scope "
      + "and 'registration-token' not member of t.scope")
  List<OAuth2AccessTokenEntity> findValidAccessTokensForUser(
    @Param("userId") String userId, @Param("timestamp") Date timestamp);

  @Query("select t from OAuth2AccessTokenEntity t "
    + "where t.authenticationHolder.userAuth.name = :userId "
    + "and t.expiration is NOT NULL "
    + "and t.expiration > :timestamp "
    + "and 'resource-token' not member of t.scope "
    + "and 'registration-token' not member of t.scope "
    + "order by t.expiration")
  Page<OAuth2AccessTokenEntity> findValidAccessTokensForUser(
    @Param("userId") String userId, @Param("timestamp") Date timestamp,
    Pageable op);

  @Query("select t from OAuth2AccessTokenEntity t "
    + "where t.authenticationHolder.clientId = :clientId "
    + "and 'resource-token' not member of t.scope "
    + "and 'registration-token' not member of t.scope "
    + "and t.expiration is NOT NULL "
    + "and t.expiration > :timestamp "
    + "order by t.expiration")
  Page<OAuth2AccessTokenEntity> findValidAccessTokensForClient(
    @Param("clientId") String clientId, @Param("timestamp") Date timestamp,
    Pageable op);

  @Query("select t from OAuth2AccessTokenEntity t "
    + "where t.authenticationHolder.userAuth.name = :userId "
    + "and 'resource-token' not member of t.scope "
    + "and 'registration-token' not member of t.scope "
    + "and t.authenticationHolder.clientId = :clientId "
    + "and t.expiration is NOT NULL "
    + "and t.expiration > :timestamp "
    + "order by t.expiration")
  Page<OAuth2AccessTokenEntity> findValidAccessTokensForUserAndClient(
    @Param("userId") String userId, @Param("clientId") String clientId,
    @Param("timestamp") Date timestamp, Pageable op);

  @Query("select distinct t from OAuth2AccessTokenEntity t "
    + "where t.expiration is NOT NULL "
    + "and t.expiration > :timestamp "
    + "and 'resource-token' not member of t.scope "
    + "and 'registration-token' not member of t.scope "
    + "order by t.expiration")
  Page<OAuth2AccessTokenEntity> findAllValidAccessTokens(
    @Param("timestamp") Date timestamp, Pageable op);

  @Query("select count(t) from OAuth2AccessTokenEntity t "
    + "where t.expiration is NOT NULL "
    + "and t.expiration > :timestamp "
    + "and 'resource-token' not member of t.scope "
    + "and 'registration-token' not member of t.scope")
  long countValidAccessTokens(@Param("timestamp") Date timestamp);

  @Query("select count(t) from OAuth2AccessTokenEntity t "
    + "where t.expiration is NOT NULL "
    + "and t.expiration > :timestamp "
    + "and t.authenticationHolder.userAuth.name = :userId "
    + "and 'resource-token' not member of t.scope "
    + "and 'registration-token' not member of t.scope ")
  long countValidAccessTokensForUser(@Param("userId") String userId,
    @Param("timestamp") Date timestamp);

  @Query("select count(t) from OAuth2AccessTokenEntity t "
    + "where t.expiration is NOT NULL "
    + "and t.expiration > :timestamp "
    + "and t.authenticationHolder.clientId = :clientId "
    + "and 'resource-token' not member of t.scope "
    + "and 'registration-token' not member of t.scope ")
  long countValidAccessTokensForClient(@Param("clientId") String clientId,
    @Param("timestamp") Date timestamp);

  @Query("select count(t) from OAuth2AccessTokenEntity t "
    + "where t.expiration is NOT NULL "
    + "and t.expiration > :timestamp "
    + "and t.authenticationHolder.userAuth.name = :userId "
    + "and t.authenticationHolder.clientId = :clientId "
    + "and 'resource-token' not member of t.scope "
    + "and 'registration-token' not member of t.scope ")
  long countValidAccessTokensForUserAndClient(@Param("userId") String userId,
    @Param("clientId") String clientId, @Param("timestamp") Date timestamp);

  @Query("select t from OAuth2AccessTokenEntity t "
      + "where t.authenticationHolder.id in ("
      + " select sua.id "
      + " from SavedUserAuthentication sua "
      + " where sua.name not in ("
      + "  select a.username "
      + "  from IamAccount a"
      + " )"
      + ")")
  List<OAuth2AccessTokenEntity> findOrphanedTokens();
  // @formatter:on

}
