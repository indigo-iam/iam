package it.infn.mw.iam.audit.events;

import it.infn.mw.iam.persistence.model.IamGroup;

public class GroupEvent extends IamAuditApplicationEvent {

  private static final long serialVersionUID = -6490018220086638357L;

  private static final String category = "Group";

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
    getData().put("category", category);
    getData().put("type", this.getClass().getSimpleName());
    getData().put("groupUuid", group.getUuid());
    getData().put("groupName", group.getName());
  }
}
