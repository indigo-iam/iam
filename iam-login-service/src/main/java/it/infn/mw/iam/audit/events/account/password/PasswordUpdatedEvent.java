package it.infn.mw.iam.audit.events.account.password;

import it.infn.mw.iam.audit.events.account.AccountEvent;
import it.infn.mw.iam.persistence.model.IamAccount;

public class PasswordUpdatedEvent extends AccountEvent {

  private static final long serialVersionUID = 3213253939764135733L;

  public PasswordUpdatedEvent(Object source, IamAccount account, String message) {
    super(source, account, message);
  }

}
