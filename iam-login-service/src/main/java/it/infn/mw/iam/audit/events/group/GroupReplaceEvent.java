package it.infn.mw.iam.audit.events.group;

import static it.infn.mw.iam.audit.IamAuditField.PREVIOUS_GROUP_NAME;
import static it.infn.mw.iam.audit.IamAuditField.PREVIOUS_GROUP_UUID;

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
    getData().put(PREVIOUS_GROUP_UUID, previousGroup.getUuid());
    getData().put(PREVIOUS_GROUP_NAME, previousGroup.getName());
  }
}
