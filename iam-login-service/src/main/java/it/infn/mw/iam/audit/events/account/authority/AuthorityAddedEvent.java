package it.infn.mw.iam.audit.events.account.authority;

import it.infn.mw.iam.persistence.model.IamAccount;

public class AuthorityAddedEvent extends AuthorityEvent {

  private static final long serialVersionUID = -4417086469498656830L;

  public AuthorityAddedEvent(Object source, IamAccount account, String message, String authority) {
    super(source, account, message, authority);
  }

}
