package it.infn.mw.iam.test.audit.event;

public interface CertificateLinkingNotificationUtil {


    default String getLinkMessage(String name, String username, String email, String subjectDn,
            String issuerDn, String organisationName) {
        return String.format(
                "The following user has linked a certificate to their account. \n\nName: %s\nUsername: %s\nEmail: %s\nSubjectDN: %s\nIssuerDN: %s\n\nThe %s registration service\n",
                name, username, email, subjectDn, issuerDn, organisationName);
    }

    default String getUnLinkMessage(String name, String username, String email, String subjectDn,
            String issuerDn, String organisationName) {
        return String.format(
                "The following user has removed a previously linked a certificate from their account. \n\nName: %s\nUsername: %s\nEmail: %s\nSubjectDN: %s\nIssuerDN: %s\n\nThe %s registration service\n",
                name, username, email, subjectDn, issuerDn, organisationName);
    }
}
