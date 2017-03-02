package it.infn.mw.iam.audit.events.account.password;

import it.infn.mw.iam.audit.events.account.AccountEvent;
import it.infn.mw.iam.persistence.model.IamAccount;

public class PasswordResetEvent extends AccountEvent {

  private static final long serialVersionUID = 1994363894536234960L;

  public PasswordResetEvent(Object source, IamAccount account, String message) {
    super(source, account, message);
  }

  public String getResetKey(){
    return getAccount().getResetKey();
  }
}
