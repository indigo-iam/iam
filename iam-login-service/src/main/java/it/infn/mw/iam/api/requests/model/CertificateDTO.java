package it.infn.mw.iam.api.requests.model;

public interface CertificateDTO {

    String getPemEncodedCertificate();

    String getSubjectDn();

    String getIssuerDn();

}
