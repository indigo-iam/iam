package it.infn.mw.iam.audit.events.account.authority;

import it.infn.mw.iam.persistence.model.IamAccount;

public class AuthorityRemovedEvent extends AuthorityEvent {

  private static final long serialVersionUID = -662056143285901405L;

  public AuthorityRemovedEvent(Object source, IamAccount account, String message, String authority) {
    super(source, account, message, authority);
  }

}
