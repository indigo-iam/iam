package it.infn.mw.iam.audit.events;

import it.infn.mw.iam.api.scim.updater.UpdaterType;
import it.infn.mw.iam.persistence.model.IamAccount;

public class AccountUpdateEvent extends AccountEvent {

  private static final long serialVersionUID = 5449634442314906657L;

  private final UpdaterType updateType;

  public AccountUpdateEvent(Object source, IamAccount account, UpdaterType updateType,
      String message) {
    super(source, account, message);
    this.updateType = updateType;
  }

  @Override
  protected void addAuditData() {
    super.addAuditData();
    getData().put("updateType", updateType.getDescription());
  }
}
