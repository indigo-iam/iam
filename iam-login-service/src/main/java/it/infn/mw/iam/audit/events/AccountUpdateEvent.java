package it.infn.mw.iam.audit.events;

import static it.infn.mw.iam.audit.IamAuditField.updateType;

import it.infn.mw.iam.api.scim.updater.UpdaterType;
import it.infn.mw.iam.persistence.model.IamAccount;

public class AccountUpdateEvent extends AccountEvent {

  private static final long serialVersionUID = 5449634442314906657L;

  private final UpdaterType type;

  public AccountUpdateEvent(Object source, IamAccount account, UpdaterType type, String message) {
    super(source, account, message);
    this.type = type;
  }

  @Override
  protected void addAuditData() {
    super.addAuditData();
    getData().put(updateType, type.getDescription());
  }
}
