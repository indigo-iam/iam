package it.infn.mw.iam.persistence.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.data.repository.query.Param;

import it.infn.mw.iam.persistence.model.SystemScope;

public interface SystemScopeRepository extends PagingAndSortingRepository<SystemScope, Long> {

  List<SystemScope> findAllOrderByIdAsc();

  Optional<SystemScope> findByValue(@Param("scope") String value);

  List<SystemScope> findByDefaultScopeTrueOrderByIdAsc();

  List<SystemScope> findByRestrictedTrueOrderByIdAsc();

  List<SystemScope> findByRestrictedFalseOrderByIdAsc();

}
