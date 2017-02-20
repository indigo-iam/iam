package it.infn.mw.iam.audit.events;

import it.infn.mw.iam.api.scim.updater.UpdaterType;
import it.infn.mw.iam.persistence.model.IamGroup;

public class GroupUpdateEvent extends GroupEvent {

  private static final long serialVersionUID = -3060371331110710895L;

  private final UpdaterType updateType;

  public GroupUpdateEvent(Object source, IamGroup group, UpdaterType updateType, String message) {
    super(source, group, message);
    this.updateType = updateType;
  }

  @Override
  protected void addAuditData() {
    super.addAuditData();
    getData().put("updateType", updateType.getDescription());
  }

}
