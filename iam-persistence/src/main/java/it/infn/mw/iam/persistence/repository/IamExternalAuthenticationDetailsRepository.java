package it.infn.mw.iam.persistence.repository;

import java.util.Optional;

import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.data.repository.query.Param;

import it.infn.mw.iam.persistence.model.IamExternalAuthenticationDetails;

public interface IamExternalAuthenticationDetailsRepository
    extends PagingAndSortingRepository<IamExternalAuthenticationDetails, Long> {

  Optional<IamExternalAuthenticationDetails> findBySavedAuthenticationId(
      @Param("savedAuthenticationId") Long savedAuthenticationId);

}
