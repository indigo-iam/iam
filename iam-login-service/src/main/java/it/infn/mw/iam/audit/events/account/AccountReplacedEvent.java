package it.infn.mw.iam.audit.events.account;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import it.infn.mw.iam.audit.utils.IamAccountSerializer;
import it.infn.mw.iam.persistence.model.IamAccount;

public class AccountReplacedEvent extends AccountEvent {

  private static final long serialVersionUID = -1605221918249294636L;

  @JsonSerialize(using=IamAccountSerializer.class)
  private final IamAccount previousAccount;

  public AccountReplacedEvent(Object source, IamAccount account, IamAccount previousAccount,
      String message) {
    super(source, account, message);
    this.previousAccount = previousAccount;
  }

  public IamAccount getPreviousAccount() {
    return previousAccount;
  }
}
