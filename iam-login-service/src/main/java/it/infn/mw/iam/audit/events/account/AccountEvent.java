package it.infn.mw.iam.audit.events.account;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import it.infn.mw.iam.audit.events.IamAuditApplicationEvent;
import it.infn.mw.iam.audit.utils.IamAccountSerializer;
import it.infn.mw.iam.persistence.model.IamAccount;

public abstract class AccountEvent extends IamAuditApplicationEvent {

  private static final long serialVersionUID = 7805974917245187812L;

  @JsonSerialize(using=IamAccountSerializer.class)
  private final IamAccount account;

  public AccountEvent(Object source, IamAccount account, String message) {
    super(IamEventCategory.ACCOUNT, source, message);
    this.account = account;
  }

  public IamAccount getAccount() {
    return account;
  }
  
}
