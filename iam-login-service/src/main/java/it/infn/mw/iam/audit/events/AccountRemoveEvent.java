package it.infn.mw.iam.audit.events;

import it.infn.mw.iam.persistence.model.IamAccount;

public class AccountRemoveEvent extends AccountEvent {

  private static final long serialVersionUID = 5302146010235357659L;

  public AccountRemoveEvent(Object source, IamAccount account, String message) {
    super(source, account, message);
  }
}
