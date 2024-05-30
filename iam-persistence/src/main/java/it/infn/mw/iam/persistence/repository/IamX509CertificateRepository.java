package it.infn.mw.iam.persistence.repository;

import java.util.Optional;

import org.springframework.data.repository.PagingAndSortingRepository;

import it.infn.mw.iam.persistence.model.IamX509Certificate;

public interface IamX509CertificateRepository
        extends PagingAndSortingRepository<IamX509Certificate, Long> {

    public Optional<IamX509Certificate> findBySubjectDnAndIssuerDn(String subjectDn, String issuerDn);
}
