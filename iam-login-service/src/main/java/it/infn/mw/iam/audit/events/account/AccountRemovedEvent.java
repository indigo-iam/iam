package it.infn.mw.iam.audit.events.account;

import it.infn.mw.iam.persistence.model.IamAccount;

public class AccountRemovedEvent extends AccountEvent {

  private static final long serialVersionUID = 5302146010235357659L;

  public AccountRemovedEvent(Object source, IamAccount account, String message) {
    super(source, account, message);
  }
}
