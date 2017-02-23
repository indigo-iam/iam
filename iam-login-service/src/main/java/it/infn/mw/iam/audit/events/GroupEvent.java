package it.infn.mw.iam.audit.events;

import static it.infn.mw.iam.audit.IamAuditField.category;
import static it.infn.mw.iam.audit.IamAuditField.groupName;
import static it.infn.mw.iam.audit.IamAuditField.groupUuid;
import static it.infn.mw.iam.audit.IamAuditField.type;

import it.infn.mw.iam.persistence.model.IamGroup;

public class GroupEvent extends IamAuditApplicationEvent {

  private static final long serialVersionUID = -6490018220086638357L;

  private static final String categoryValue = "GROUP";

  private final IamGroup group;

  public GroupEvent(Object source, IamGroup group, String message) {
    super(source, message);
    this.group = group;
  }

  public IamGroup getgroup() {
    return group;
  }

  @Override
  protected void addAuditData() {
    super.addAuditData();
    getData().put(category, categoryValue);
    getData().put(type, this.getClass().getSimpleName());
    getData().put(groupUuid, group.getUuid());
    getData().put(groupName, group.getName());
  }
}
