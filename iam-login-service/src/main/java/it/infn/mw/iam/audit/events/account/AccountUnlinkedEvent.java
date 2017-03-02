package it.infn.mw.iam.audit.events.account;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo.ExternalAuthenticationType;
import it.infn.mw.iam.persistence.model.IamAccount;

public class AccountUnlinkedEvent extends AccountEvent {

  private static final long serialVersionUID = -1605221918249294636L;

  @JsonIgnoreProperties({"email", "givenName", "familyName", "issuer", "subject"})
  private final ExternalAuthenticationType externalAuthenticationType;
  
  private final String issuer;
  private final String subject;

  public AccountUnlinkedEvent(Object source, IamAccount account,
      ExternalAuthenticationType accountType, String issuer, String subject, String message) {
    super(source, account, message);
    this.externalAuthenticationType = accountType;
    this.issuer = issuer;
    this.subject = subject;
  }

  public ExternalAuthenticationType getExternalAuthenticationType() {
    return externalAuthenticationType;
  }

  public String getIssuer() {
    return issuer;
  }

  public String getSubject() {
    return subject;
  }

}
