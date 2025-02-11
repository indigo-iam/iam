package it.infn.mw.iam.persistence.repository;

import java.util.List;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.PagingAndSortingRepository;

import it.infn.mw.iam.persistence.model.AuthenticationHolder;

public interface AuthenticationHolderRepository extends PagingAndSortingRepository<AuthenticationHolder, Long> {

  @Query("select a from AuthenticationHolderEntity a "
      + "where a.id not in (select t.authenticationHolder.id from OAuth2AccessTokenEntity t) "
      + "and a.id not in (select r.authenticationHolder.id from OAuth2RefreshTokenEntity r) "
      + "and a.id not in (select c.authenticationHolder.id from AuthorizationCodeEntity c)")
  List<AuthenticationHolder> getUnused();
}
