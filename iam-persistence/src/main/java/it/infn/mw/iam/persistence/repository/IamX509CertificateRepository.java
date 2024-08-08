package it.infn.mw.iam.persistence.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.data.repository.query.Param;

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamX509Certificate;

public interface IamX509CertificateRepository
    extends PagingAndSortingRepository<IamX509Certificate, Long> {

  @Query("select c.account from IamX509Certificate c where c.subjectDn = :subject")
  List<IamAccount> findBySubject(@Param("subject") String subject);

  @Query("select c from IamX509Certificate c where c.subjectDn = :subject and c.issuerDn = :issuer")
  Optional<IamX509Certificate> findBySubjectAndIssuer(@Param("subject") String subject,
      @Param("issuer") String issuer);

}
