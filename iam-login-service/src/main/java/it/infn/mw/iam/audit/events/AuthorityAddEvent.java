package it.infn.mw.iam.audit.events;

import it.infn.mw.iam.audit.IamAuditField;
import it.infn.mw.iam.persistence.model.IamAccount;

public class AuthorityAddEvent extends AccountEvent {

  private static final long serialVersionUID = -4417086469498656830L;
  private final String authority;

  public AuthorityAddEvent(Object source, IamAccount account, String authority, String message) {
    super(source, account, message);
    this.authority = authority;
  }

  @Override
  protected void addAuditData() {
    super.addAuditData();
    getData().put(IamAuditField.authority, authority);
  }

}
