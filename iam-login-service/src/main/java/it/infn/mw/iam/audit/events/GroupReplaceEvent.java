package it.infn.mw.iam.audit.events;

import static it.infn.mw.iam.audit.IamAuditField.previousGroupName;
import static it.infn.mw.iam.audit.IamAuditField.previousGroupUuid;

import it.infn.mw.iam.persistence.model.IamGroup;

public class GroupReplaceEvent extends GroupEvent {

  private static final long serialVersionUID = -2464733224199680363L;

  private final IamGroup previousGroup;

  public GroupReplaceEvent(Object source, IamGroup group, IamGroup previousGroup, String message) {
    super(source, group, message);
    this.previousGroup = previousGroup;
  }

  @Override
  protected void addAuditData() {
    super.addAuditData();
    getData().put(previousGroupUuid, previousGroup.getUuid());
    getData().put(previousGroupName, previousGroup.getName());
  }
}
