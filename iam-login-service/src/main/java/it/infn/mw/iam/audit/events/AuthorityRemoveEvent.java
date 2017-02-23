package it.infn.mw.iam.audit.events;

import it.infn.mw.iam.audit.IamAuditField;
import it.infn.mw.iam.persistence.model.IamAccount;

public class AuthorityRemoveEvent extends AccountEvent {

  private static final long serialVersionUID = -662056143285901405L;
  private final String authority;

  public AuthorityRemoveEvent(Object source, IamAccount account, String authority, String message) {
    super(source, account, message);
    this.authority = authority;
  }

  @Override
  protected void addAuditData() {
    super.addAuditData();
    getData().put(IamAuditField.authority, authority);
  }

}
