package it.infn.mw.iam.persistence.repository;

import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.data.repository.query.Param;

import java.util.Date;
import java.util.List;

public interface IamOAuthRefreshTokenRepository
    extends PagingAndSortingRepository<OAuth2RefreshTokenEntity, Long> {

  @Query("select count(t) from OAuth2RefreshTokenEntity t")
  int countAllTokens();

  @Query("select t from OAuth2RefreshTokenEntity t where t.authenticationHolder.userAuth.name = :userId "
      + "and (t.expiration is NULL or t.expiration > :timestamp)")
  List<OAuth2RefreshTokenEntity> findValidRefreshTokensForUser(@Param("userId") String userId,
      @Param("timestamp") Date timestamp);

  @Query("select t from OAuth2RefreshTokenEntity t "
      + "where (t.authenticationHolder.userAuth.name = :userId) "
      + "and (t.expiration is NULL or t.expiration > :timestamp) " + " order by t.expiration")
  Page<OAuth2RefreshTokenEntity> findValidRefreshTokensForUser(@Param("userId") String userId,
      @Param("timestamp") Date timestamp, Pageable op);

  @Query("select t from OAuth2RefreshTokenEntity t "
      + "where (t.authenticationHolder.clientId = :clientId) "
      + "and (t.expiration is NULL or t.expiration > :timestamp) " + "order by t.expiration")
  Page<OAuth2RefreshTokenEntity> findValidRefreshTokensForClient(@Param("clientId") String clientId,
      @Param("timestamp") Date timestamp, Pageable op);

  @Query("select t from OAuth2RefreshTokenEntity t "
      + "where (t.authenticationHolder.userAuth.name = :userId) "
      + "and (t.authenticationHolder.clientId = :clientId) "
      + "and (t.expiration is NULL or t.expiration > :timestamp) " + "order by t.expiration")
  Page<OAuth2RefreshTokenEntity> findValidRefreshTokensForUserAndClient(
      @Param("userId") String userId, @Param("clientId") String clientId,
      @Param("timestamp") Date timestamp, Pageable op);

  @Query("select t from OAuth2RefreshTokenEntity t "
      + "where (t.expiration is NULL or t.expiration > :timestamp) " + "order by t.expiration")
  Page<OAuth2RefreshTokenEntity> findAllValidRefreshTokens(@Param("timestamp") Date timestamp,
      Pageable op);
}
