package it.infn.mw.iam.persistence.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.data.repository.query.Param;

import it.infn.mw.iam.core.IamRegistrationRequestStatus;
import it.infn.mw.iam.persistence.model.IamRegistrationRequest;

public interface IamRegistrationRequestRepository
    extends PagingAndSortingRepository<IamRegistrationRequest, Long> {

  Optional<List<IamRegistrationRequest>> findByStatus(
      @Param("status") IamRegistrationRequestStatus status);

  Optional<IamRegistrationRequest> findByUuid(@Param("uuid") String uuid);

  @Query("select r from IamRegistrationRequest r join r.account a where a.confirmationKey = :confirmationKey")
  Optional<IamRegistrationRequest> findByAccountConfirmationKey(
      @Param("confirmationKey") String confirmationKey);

  @Query("select r from IamRegistrationRequest r where r.status = it.infn.mw.iam.core.IamRegistrationRequestStatus.NEW or r.status = it.infn.mw.iam.core.IamRegistrationRequestStatus.CONFIRMED")
  Optional<List<IamRegistrationRequest>> findPendingRequests();
}
