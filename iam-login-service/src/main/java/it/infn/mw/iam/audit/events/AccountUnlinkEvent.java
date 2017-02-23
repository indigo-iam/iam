package it.infn.mw.iam.audit.events;

import static it.infn.mw.iam.audit.IamAuditField.extAccountIssuer;
import static it.infn.mw.iam.audit.IamAuditField.extAccountSubject;
import static it.infn.mw.iam.audit.IamAuditField.extAccountType;

import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo.ExternalAuthenticationType;
import it.infn.mw.iam.persistence.model.IamAccount;

public class AccountUnlinkEvent extends AccountEvent {

  private static final long serialVersionUID = -1605221918249294636L;

  private final ExternalAuthenticationType accountType;
  private final String issuer;
  private final String subject;

  public AccountUnlinkEvent(Object source, IamAccount account,
      ExternalAuthenticationType accountType, String issuer, String subject, String message) {
    super(source, account, message);
    this.accountType = accountType;
    this.issuer = issuer;
    this.subject = subject;
  }

  @Override
  protected void addAuditData() {
    super.addAuditData();
    getData().put(extAccountType, accountType);
    getData().put(extAccountIssuer, issuer);
    getData().put(extAccountSubject, subject);
  }
}
