package it.infn.mw.iam.audit.events;

import it.infn.mw.iam.persistence.model.IamAccount;

public class AccountEvent extends IamAuditApplicationEvent {

  private static final long serialVersionUID = 7805974917245187812L;

  private static final String category = "Account";

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
    getData().put("category", category);
    getData().put("type", this.getClass().getSimpleName());
    getData().put("accountUuid", account.getUuid());
    getData().put("user", account.getUsername());
  }
}
