package it.infn.mw.iam.persistence.repository;

import java.util.Date;
import java.util.List;

import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.data.repository.query.Param;

public interface IamOAuthAccessTokenRepository
    extends PagingAndSortingRepository<OAuth2AccessTokenEntity, Long> {

  @Query("select count(t) from OAuth2AccessTokenEntity t")
  int countAllTokens();

  @Query("select t from OAuth2AccessTokenEntity t where t.authenticationHolder.userAuth.name = :userId "
      + "and (t.expiration is NULL or t.expiration > :timestamp)")
  List<OAuth2AccessTokenEntity> findValidAccessTokensForUser(@Param("userId") String userId,
      @Param("timestamp") Date timestamp);

  @Query("select t from OAuth2AccessTokenEntity t "
      + "where (t.authenticationHolder.userAuth.name LIKE %:userId%) "
      + "and (t.authenticationHolder.clientId LIKE %:clientId%) "
      + "and (t.expiration is NULL or t.expiration > :timestamp)")
  Page<OAuth2AccessTokenEntity> findValidTokensForUserAndClientLike(@Param("userId") String userId,
      @Param("clientId") String clientId, @Param("timestamp") Date timestamp, Pageable op);
}
