package it.infn.mw.iam.audit.events;

import static it.infn.mw.iam.audit.IamAuditField.accountUuid;
import static it.infn.mw.iam.audit.IamAuditField.category;
import static it.infn.mw.iam.audit.IamAuditField.type;
import static it.infn.mw.iam.audit.IamAuditField.user;

import it.infn.mw.iam.persistence.model.IamAccount;

public class AccountEvent extends IamAuditApplicationEvent {

  private static final long serialVersionUID = 7805974917245187812L;

  private static final String categoryValue = "ACCOUNT";

  private final IamAccount account;

  public AccountEvent(Object source, IamAccount account, String message) {
    super(source, message);
    this.account = account;
  }

  public IamAccount getAccount() {
    return account;
  }

  @Override
  protected void addAuditData() {
    super.addAuditData();
    getData().put(category, categoryValue);
    getData().put(type, this.getClass().getSimpleName());
    getData().put(accountUuid, account.getUuid());
    getData().put(user, account.getUsername());
  }
}
