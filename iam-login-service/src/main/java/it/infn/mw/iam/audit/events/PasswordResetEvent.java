package it.infn.mw.iam.audit.events;

import static it.infn.mw.iam.audit.IamAuditField.resetKey;

import it.infn.mw.iam.persistence.model.IamAccount;

public class PasswordResetEvent extends AccountEvent {

  private static final long serialVersionUID = 1994363894536234960L;

  public PasswordResetEvent(Object source, IamAccount account, String message) {
    super(source, account, message);
  }

  @Override
  protected void addAuditData() {
    super.addAuditData();
    getData().put(resetKey, getAccount().getResetKey());
  }

}
