package it.infn.mw.iam.audit.events.account;

import static it.infn.mw.iam.audit.IamAuditField.ACCOUNT_UUID;
import static it.infn.mw.iam.audit.IamAuditField.CATEGORY;
import static it.infn.mw.iam.audit.IamAuditField.TYPE;
import static it.infn.mw.iam.audit.IamAuditField.USER;

import it.infn.mw.iam.audit.events.IamAuditApplicationEvent;
import it.infn.mw.iam.persistence.model.IamAccount;

public class AccountEvent extends IamAuditApplicationEvent {

  private static final long serialVersionUID = 7805974917245187812L;

  private final IamAccount account;

  public AccountEvent(Object source, IamAccount account, String message) {
    super(IamEventCategory.ACCOUNT, source, message);
    this.account = account;
  }

  public IamAccount getAccount() {
    return account;
  }
  
  @Override
  protected void addAuditData() {
    super.addAuditData();
    getData().put(CATEGORY, getCategory().name());
    getData().put(TYPE, this.getClass().getSimpleName());
    getData().put(ACCOUNT_UUID, account.getUuid());
    getData().put(USER, account.getUsername());
  }
}
