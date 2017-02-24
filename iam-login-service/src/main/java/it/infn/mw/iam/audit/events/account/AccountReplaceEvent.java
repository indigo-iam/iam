package it.infn.mw.iam.audit.events.account;

import static it.infn.mw.iam.audit.IamAuditField.PREVIOUS_ACCOUNT_USERNAME;
import static it.infn.mw.iam.audit.IamAuditField.PREVIOUS_ACCOUNT_UUID;

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
    getData().put(PREVIOUS_ACCOUNT_UUID, previousAccount.getUuid());
    getData().put(PREVIOUS_ACCOUNT_USERNAME, previousAccount.getUsername());
  }
}
