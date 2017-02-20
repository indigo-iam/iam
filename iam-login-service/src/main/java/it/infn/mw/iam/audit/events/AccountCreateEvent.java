package it.infn.mw.iam.audit.events;

import it.infn.mw.iam.persistence.model.IamAccount;

public class AccountCreateEvent extends AccountEvent {

  private static final long serialVersionUID = 5591392339615932111L;

  public AccountCreateEvent(Object source, IamAccount account, String message) {
    super(source, account, message);
  }
}
