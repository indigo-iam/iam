package it.infn.mw.iam.audit.events.account.authority;

import it.infn.mw.iam.audit.events.account.AccountEvent;
import it.infn.mw.iam.persistence.model.IamAccount;

public abstract class AuthorityEvent extends AccountEvent {

  private static final long serialVersionUID = 1L;
  
  protected final String authority;
  
  public AuthorityEvent(Object source, IamAccount account, String message, String authority) {
    super(source, account, message);
    this.authority = authority;
  }

  public String getAuthority() {
    return authority;
  }

}
