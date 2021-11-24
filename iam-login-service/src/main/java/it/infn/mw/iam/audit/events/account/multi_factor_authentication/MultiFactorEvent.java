package it.infn.mw.iam.audit.events.account.multi_factor_authentication;

import it.infn.mw.iam.audit.events.account.AccountEvent;
import it.infn.mw.iam.persistence.model.IamAccount;

public class MultiFactorEvent extends AccountEvent {

  // TODO determine this
  // private static final long serialVersionUID = 1L;

  protected MultiFactorEvent(Object source, IamAccount account, String message) {
    super(source, account, message);
  }
}
