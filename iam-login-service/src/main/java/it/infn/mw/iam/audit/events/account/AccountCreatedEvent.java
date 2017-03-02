package it.infn.mw.iam.audit.events.account;

import it.infn.mw.iam.persistence.model.IamAccount;

public class AccountCreatedEvent extends AccountEvent {

  private static final long serialVersionUID = 5591392339615932111L;

  public AccountCreatedEvent(Object source, IamAccount account, String message) {
    super(source, account, message);
  }
}
