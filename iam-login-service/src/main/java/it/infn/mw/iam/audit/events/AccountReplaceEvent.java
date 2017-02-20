package it.infn.mw.iam.audit.events;

import it.infn.mw.iam.persistence.model.IamAccount;

public class AccountReplaceEvent extends AccountEvent {

  private static final long serialVersionUID = -1605221918249294636L;

  private final IamAccount previousAccount;

  public AccountReplaceEvent(Object source, IamAccount account, IamAccount previousAccount,
      String message) {
    super(source, account, message);
    this.previousAccount = previousAccount;
  }

  @Override
  protected void addAuditData() {
    super.addAuditData();
    getData().put("previousAccountUuid", previousAccount.getUuid());
    getData().put("previousAccountUsername", previousAccount.getUsername());
  }
}
