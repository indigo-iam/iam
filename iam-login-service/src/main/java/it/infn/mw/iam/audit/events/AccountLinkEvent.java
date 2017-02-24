package it.infn.mw.iam.audit.events;

import static it.infn.mw.iam.audit.IamAuditField.EXT_ACCOUNT_ISSUER;
import static it.infn.mw.iam.audit.IamAuditField.EXT_ACCOUNT_SUBJECT;
import static it.infn.mw.iam.audit.IamAuditField.EXT_ACCOUNT_TYPE;

import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo;
import it.infn.mw.iam.persistence.model.IamAccount;

public class AccountLinkEvent extends AccountEvent {

  private static final long serialVersionUID = -1605221918249294636L;

  private final ExternalAuthenticationRegistrationInfo externalAccountInfo;

  public AccountLinkEvent(Object source, IamAccount account,
      ExternalAuthenticationRegistrationInfo externalAccountInfo, String message) {
    super(source, account, message);
    this.externalAccountInfo = externalAccountInfo;
  }

  @Override
  protected void addAuditData() {
    super.addAuditData();
    getData().put(EXT_ACCOUNT_ISSUER, externalAccountInfo.getIssuer());
    getData().put(EXT_ACCOUNT_SUBJECT, externalAccountInfo.getSubject());
    getData().put(EXT_ACCOUNT_TYPE, externalAccountInfo.getType().toString());
  }
}
